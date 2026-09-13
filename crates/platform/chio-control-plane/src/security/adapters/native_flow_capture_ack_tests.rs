// Real committed quota must survive callback failure and substituted replies.
use super::*;
use chio_kernel::budget_store::{BudgetInvocationCaptureDecision, BudgetMutationKind};
use chio_kernel::AdmissionBudgetCapture;
use chio_store_sqlite::admission_operation_store::NativeDispatchCaptureResponseTestFault as Fault;

#[test]
fn native_capture_acknowledgement_faults_preserve_committed_accounting() -> TestResult {
    for egress in [false, true] {
        for fault in Fault::ALL.into_iter().filter(|fault| !fault.is_readback()) {
            run_fault(super::super::super::public_fixture()?, egress, fault)?;
        }
    }
    Ok(())
}

#[test]
fn native_capture_readback_faults_preserve_committed_accounting() -> TestResult {
    for egress in [false, true] {
        for fault in Fault::ALL.into_iter().filter(|fault| fault.is_readback()) {
            run_fault(super::super::super::public_fixture()?, egress, fault)?;
        }
    }
    Ok(())
}

#[test]
fn native_capture_lost_ack_retains_owned_dpop_without_reclaim() -> TestResult {
    for egress in [false, true] {
        let mut fixture = Fixture::new_with_seed_and_dpop(
            std::array::from_fn(|_| InformationLabel::bottom()),
            |_| Ok(None),
            true,
        )?;
        fixture.configure_native_capture_dpop()?;
        run_fault(fixture, egress, Fault::CaptureError)?;
    }
    Ok(())
}

fn expected_reason(fault: Fault) -> &'static str {
    match fault {
        Fault::CaptureError => "acknowledgement loss after commit",
        Fault::CapturePanic => "native capture callback panicked",
        Fault::CaptureOperation => "different operation successor",
        Fault::CaptureReplay => "historical replay acknowledgement",
        Fault::CaptureHold
        | Fault::CaptureBinding
        | Fault::CaptureEvent
        | Fault::CaptureAuthority
        | Fault::CaptureGuarantee => "actual invocation custody",
        Fault::CaptureCommitIndex
        | Fault::CaptureTimestamp
        | Fault::CaptureQuota
        | Fault::CaptureMissingQuota
        | Fault::CaptureCost
        | Fault::ReadChanged => "differs from committed budget readback",
        Fault::ReadMissing => "budget readback is absent",
        Fault::ReadError => "readback error after commit",
        Fault::ReadPanic => "store callback panicked",
    }
}

fn run_fault(mut fixture: Fixture, egress: bool, fault: Fault) -> TestResult {
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::super::registry(egress, InformationLabel::bottom())?,
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
        .inject_native_capture_response_failure_for_test(fault)?;
    let attempts = Arc::new(AtomicUsize::new(0));
    let successes = Arc::new(AtomicUsize::new(0));
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new({
            let attempts = attempts.clone();
            let successes = successes.clone();
            move |authority| {
                attempts.fetch_add(1, Ordering::SeqCst);
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
        .clear_native_capture_response_failure_for_test()?;
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "{fault:?}, egress={egress}"
    );
    assert!(response.output.is_none());
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains(expected_reason(fault))),
        "{fault:?}, egress={egress}: {:?}",
        response.reason
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(successes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("committed operation after reply failure")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
    let ledger = store
        .load_native_dispatch_ledger(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("committed preparation")?;
    assert_eq!(
        operation.native_dispatch_ledger_digest(),
        Some(&ledger.record_digest)
    );
    let value: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
    assert_eq!(value["egress_commitment"].is_null(), !egress);
    let capture = store
        .load_native_dispatch_capture(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("independent capture readback after clearing reply fault")?;
    assert_eq!(capture.operation, operation);
    assert!(matches!(
        capture.decision,
        BudgetInvocationCaptureDecision::Captured(_)
    ));
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
        1
    );
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("committed capture quota")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 1)
    );
    if original.matching_grants_require_dpop() {
        let (_, claims) = store
            .load_dpop_replay_claim_history(operation.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("owned DPoP after acknowledgement loss")?;
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].disposition, chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition::RetainedAfterDispatchCommit);
    }
    drop(store);
    reopen_capture(fixture, &capture, &ledger)
}

fn reopen_capture(
    fixture: Fixture,
    expected: &AdmissionBudgetCapture,
    ledger: &chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1,
) -> TestResult {
    let old_fence = fixture.authority.mutation_fence();
    let Fixture {
        kernel,
        authority,
        _directory,
        ..
    } = fixture;
    drop(kernel);
    drop(authority);
    let reopened = SqliteAuthorityStore::open_serving(
        _directory.path().join("admission.db"),
        _directory.path().join("locks"),
    )?;
    let fence = reopened.mutation_fence();
    assert!(fence.owner_epoch > old_fence.owner_epoch);
    let store = reopened.admission_operation_store();
    let id = expected.operation.binding().operation_id();
    assert!(store
        .load_native_dispatch_capture(id, &old_fence, now_ms()?)
        .is_err());
    assert_eq!(
        store
            .load_native_dispatch_capture(id, &fence, now_ms()?)?
            .as_ref(),
        Some(expected)
    );
    assert_eq!(
        store
            .load_native_dispatch_ledger(id, &fence, now_ms()?)?
            .as_ref(),
        Some(ledger)
    );
    let usage = reopened
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            expected.operation.binding().capability_id().as_str(),
            0,
        ))?
        .ok_or("captured quota after new-owner reopen")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 1)
    );
    Ok(())
}
