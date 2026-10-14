// Original consumption survives failed capture; output and use-outcome roll back together.
use super::*;

#[test]
fn native_egress_event_is_stamped_after_queued_valid_declassification() -> TestResult {
    let (fixture, _) = profile(false, 300)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let prepared_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let _observer = fixture
        .kernel
        .observe_native_egress_commit_for_test(Arc::new({
            let calls = calls.clone();
            let prepared_at = prepared_at.clone();
            move |time| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    prepared_at.store(time, Ordering::SeqCst);
                    // The signed grant, native lease and fence remain valid for
                    // much longer than this real scheduling delay. Only the old
                    // pre-writer event clock is stale at the physical writer.
                    std::thread::sleep(std::time::Duration::from_millis(6_050));
                }
            }
        }))?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "the prepared event was not observed"
    );
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("queued original absent")?;
    let (_, history) = store
        .load_native_security_egress(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("queued original egress absent")?;
    let commitment = history
        .ok_or("queued original history absent")?
        .commitment
        .ok_or("queued original commitment absent")?;
    let consumption = commitment
        .declassification
        .ok_or("queued original consumption absent")?;
    assert!(
        commitment.commitment.committed_at_unix_ms > prepared_at.load(Ordering::SeqCst) + 5_000,
    );
    assert_eq!(
        consumption.consumption.consumed_at_unix_ms,
        commitment.commitment.committed_at_unix_ms,
    );
    assert_eq!(
        consumption.receipt.occurred_at_unix_ms,
        commitment.commitment.committed_at_unix_ms,
    );
    assert!(operation.dispatch_commit().is_some());
    Ok(())
}

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

#[test]
fn missing_disclosure_grant_attests_native_policy_before_dispatch() -> TestResult {
    let (mut fixture, _) = profile(false, 300)?;
    let original_capability = fixture.request.capability.clone();
    fixture.request.declassification_grant = None;
    fixture.request.execution_nonce = None;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(response.receipt.capability_id, original_capability.id);
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native missing-grant original custody absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    retained.validate_request_material(&fixture.request)?;
    retained.validate_native_security_context(&fixture.context)?;
    retained.validate_native_security_authority(&fixture.binding)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert!(
        response
            .receipt
            .evidence
            .iter()
            .any(|guard| guard.guard_name == "native-flow-resolver"
                && !guard.verdict
                && guard.details.as_deref() == Some("policy_flow_violation")),
        "native policy refusal lacks a fixed signed owner witness"
    );
    Ok(())
}
