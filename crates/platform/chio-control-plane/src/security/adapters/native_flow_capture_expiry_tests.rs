// Runtime expiry after the final state verification must roll back real capture.
use super::*;
use chio_kernel::budget_store::BudgetMutationKind;

#[test]
fn runtime_expiry_after_native_verification_rolls_back_physical_capture() -> TestResult {
    let mut fixture = Fixture::combined_native_credentials()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::super::super::registry(false, InformationLabel::bottom())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(resolver.clone());
    fixture
        .authority
        .admission_operation_store()
        .inject_native_capture_runtime_expiry_for_test()?;
    let successes = Arc::new(AtomicUsize::new(0));
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new({
            let successes = successes.clone();
            move |authority| {
                resolver
                    .prepare_dispatch(authority.prepare_egress()?)
                    .and_then(|prepared| prepared.capture_invocation(authority))
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                successes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    fixture
        .authority
        .admission_operation_store()
        .clear_native_capture_runtime_expiry_for_test()?;
    assert_eq!(
        successes.load(Ordering::SeqCst),
        0,
        "expired runtime evidence committed capture"
    );
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(
        response.reason.as_deref().is_some_and(|reason| {
            reason.contains("native capture rejected after runtime expiry cutpoint:")
                && reason.contains("native capture runtime evidence expired before commit")
        }),
        "wrong denial: {:?}",
        response.reason
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original failed capture")?;
    assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(store
        .load_native_dispatch_capture(operation.binding().operation_id(), &fence, now_ms()?,)?
        .is_none());
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("held quota")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (1, 0)
    );
    let events = fixture.authority.budget_store().list_mutation_events(
        16,
        Some(&fixture.request.capability.id),
        Some(0),
    )?;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == BudgetMutationKind::CaptureInvocation)
            .count(),
        0
    );
    let (_, runtime) = store
        .load_runtime_participant_history(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("retained runtime")?;
    let (_, approval) = store
        .load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &fence,
            now_ms()?,
        )?
        .ok_or("retained approval")?;
    let (_, dpop) = store
        .load_dpop_replay_claim_history(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("retained DPoP")?;
    assert_eq!((runtime.len(), approval.len(), dpop.len()), (1, 1, 1));
    assert_eq!(
        runtime[0].disposition,
        RuntimeParticipantDisposition::ReservedBeforeDispatch
    );
    assert_eq!(
        approval[0].disposition,
        GovernedApprovalClaimDisposition::ReservedBeforeDispatch
    );
    assert_eq!(dpop[0].disposition, chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition::ReservedBeforeDispatch);
    let ledger = store
        .load_native_dispatch_ledger(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("preparation survived capture rollback")?;
    drop(store);
    assert_eq!(
        fixture.reopen_dispatch_ledger(&ledger.operation_id, |_| Ok(()))?,
        ledger
    );
    Ok(())
}
