// Original consumption survives failed capture; output and use-outcome roll back together.
use super::*;

fn pending_use(fixture: &Fixture) -> TestResult {
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (state, evidence): (String, i64) = connection.query_row(
        "SELECT state, (SELECT COUNT(*) FROM security_participant_state_declassification_receipt_outbox)
         FROM security_participant_state_declassification_uses", [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((state.as_str(), evidence), ("consumed_pending_dispatch", 1));
    Ok(())
}

#[test]
fn native_declassification_expiry_at_final_commit_retains_consumption_without_capture() -> TestResult
{
    let (mut fixture, authority) = profile(false, 45)?;
    let resolver = Arc::new(resolver(&fixture, &authority)?);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(resolver.clone());
    // The existing deny-only checkpoint exposes the exact physical error.
    // Success acceptance is covered separately through the public connector.
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new(move |authority| {
            resolver
                .prepare_dispatch(authority.prepare_egress()?)
                .and_then(|prepared| prepared.capture_invocation(authority))
                .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
            Ok(())
        }));
    let store = fixture.authority.admission_operation_store();
    store.inject_native_capture_declassification_expiry_for_test()?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    store.clear_native_capture_declassification_expiry_for_test()?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(
        response.reason.as_deref().is_some_and(|reason| reason
            .contains("native capture rejected after declassification expiry cutpoint:")
            && reason.contains("native declassification grant is not currently valid")),
        "{:?}",
        response.reason
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    pending_use(&fixture)?;
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original failed capture")?;
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(store
        .load_native_dispatch_capture(operation.binding().operation_id(), &fence, now_ms()?)?
        .is_none());
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("quota")?;
    assert_eq!(usage.captured_invocations, 0);
    let observation = store.observe_native_security_flow(
        &fixture.binding,
        &crate::security::adapters::flow_key(fixture.context.as_v1()),
        &fence,
        now_ms()?,
    )?;
    assert_eq!(
        observation.snapshot().ok_or("taint")?.principal_label,
        restricted_label()
    );
    Ok(())
}

#[test]
fn native_declassification_output_fault_rolls_back_outcome_without_refunding_use() -> TestResult {
    use chio_store_sqlite::admission_operation_store::NativeOutputJoinTestFault;
    let (fixture, _) = profile(false, 300)?;
    let store = fixture.authority.admission_operation_store();
    store.inject_native_output_join_failure_for_test(NativeOutputJoinTestFault::AfterRows)?;
    let result = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
    store.clear_native_output_join_failure_for_test()?;
    match result {
        Ok(response) => {
            assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
            assert!(response.output.is_none());
        }
        Err(error) => assert!(
            matches!(
                error,
                KernelError::SecurityDispatchOutcomeRecoveryRequired(_)
            ),
            "{error}"
        ),
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    pending_use(&fixture)?;
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original output fault")?;
    assert!(operation.dispatch_commit().is_some());
    assert!(store
        .load_native_security_output_join(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("original output operation")?
        .1
        .is_none());
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("captured quota")?;
    assert_eq!(usage.captured_invocations, 1);
    Ok(())
}
