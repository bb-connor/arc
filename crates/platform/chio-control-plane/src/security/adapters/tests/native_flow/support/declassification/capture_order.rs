// A clean pre-commit rejection never leaves consumed downgrade or egress custody.
use super::*;
use chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimDisposition;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantDisposition;
use chio_store_sqlite::admission_operation_store::NativeDispatchLedgerTestFault;
use std::sync::Mutex;

// The combined profile accepts its runtime report through epoch + 60s.
const RUNTIME_REPORT_EXPIRED_AT_MS: u64 = 60_001;
const RUNTIME_EXPIRED: &str =
    "internal error: runtime pheromone policy revalidation failed: runtime_pheromone_advisory_stale";
const RECONCILIATION_REQUIRED: &str = "security dispatch outcome requires reconciliation: security native dispatch capture callback failed; authoritative recovery required";
const COMPENSATED_REPLAY: &str =
    "durable admission failed: request replay is retained in state CompensatedBeforeDispatch";

struct Custody {
    state: AdmissionOperationState,
    uses: Vec<String>,
    declassified_egress: bool,
    ledger: bool,
    quota: (u64, u64),
    runtime: Vec<RuntimeParticipantDisposition>,
    approval: Vec<GovernedApprovalClaimDisposition>,
    dpop: Vec<DpopReplayClaimDisposition>,
}

fn custody(fixture: &Fixture) -> TestResult<Custody> {
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let now = fixture.clock.snapshot();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now,
        )?
        .ok_or("original declassified operation")?;
    assert!(operation.dispatch_commit().is_none());
    let id = operation.binding().operation_id();
    let declassified_egress = store
        .load_native_security_egress(id, &fence, now)?
        .ok_or("original egress operation")?
        .1
        .and_then(|history| history.commitment)
        .is_some_and(|commitment| commitment.declassification.is_some());
    let ledger = store
        .load_native_dispatch_ledger(id, &fence, now)?
        .is_some();
    let quota = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .map_or((0, 0), |usage| {
            (
                u64::from(usage.reserved_invocations),
                u64::from(usage.captured_invocations),
            )
        });
    let (_, runtime) = store
        .load_runtime_participant_history(id, &fence, now)?
        .ok_or("runtime history")?;
    let (_, approval) = store
        .load_governed_approval_claim_history(id, &fence, now)?
        .ok_or("approval history")?;
    let (_, dpop) = store
        .load_dpop_replay_claim_history(id, &fence, now)?
        .ok_or("DPoP history")?;
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement =
        connection.prepare("SELECT state FROM security_participant_state_declassification_uses")?;
    let uses = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Custody {
        state: operation.state(),
        uses,
        declassified_egress,
        ledger,
        quota,
        runtime: runtime.into_iter().map(|claim| claim.disposition).collect(),
        approval: approval
            .into_iter()
            .map(|claim| claim.disposition)
            .collect(),
        dpop: dpop.into_iter().map(|claim| claim.disposition).collect(),
    })
}

fn assert_released(custody: &Custody) {
    assert_eq!(
        custody.state,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(custody.quota, (0, 0));
    assert_eq!(
        custody.runtime,
        [RuntimeParticipantDisposition::ReleasedBeforeDispatch]
    );
    assert_eq!(
        custody.approval,
        [GovernedApprovalClaimDisposition::ReleasedBeforeDispatch]
    );
    assert_eq!(
        custody.dpop,
        [DpopReplayClaimDisposition::ReleasedBeforeDispatch]
    );
}

#[test]
fn native_declassification_credential_expiry_before_capture_consumes_no_authority() -> TestResult {
    let (mut fixture, signer) = profile(true, 300)?;
    // Keep the 60s fence and operation lease one millisecond past the report.
    fixture.clock.advance_to(now_ms()? + 2)?;
    let resolver = Arc::new(resolver(&fixture, &signer)?);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(resolver.clone());
    let failure = Arc::new(Mutex::new(None));
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new({
            let clock = fixture.clock.clone();
            let failure = failure.clone();
            move |authority| {
                let prepared = resolver
                    .prepare_dispatch(authority.prepare_egress()?)
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                let expired = now_ms().map_err(|error| KernelError::Internal(error.to_string()))?
                    + RUNTIME_REPORT_EXPIRED_AT_MS;
                clock
                    .advance_to(expired)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                let error = match prepared.capture_invocation(authority) {
                    Ok(_) => {
                        return Err(KernelError::Internal(
                            "expired runtime evidence was captured".into(),
                        ))
                    }
                    Err(error) => error.to_string(),
                };
                if let Ok(mut slot) = failure.lock() {
                    *slot = Some(error.clone());
                }
                Err(KernelError::GuardDenied(error))
            }
        }));
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    // The prepared capture itself observed the lapsed runtime credential.
    assert_eq!(
        failure
            .lock()
            .map_err(|_| "capture failure record poisoned")?
            .as_deref(),
        Some(RUNTIME_EXPIRED)
    );
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some(format!("guard denied the request: {RUNTIME_EXPIRED}").as_str())
    );
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let after = custody(&fixture)?;
    // A definite pre-commit rejection compensated and released the credentials.
    assert_released(&after);
    assert_eq!(
        after.uses,
        Vec::<String>::new(),
        "a clean pre-commit rejection retained consumed declassification authority"
    );
    assert!(
        !after.declassified_egress,
        "a clean pre-commit rejection retained committed declassified egress"
    );
    assert!(
        !after.ledger,
        "a clean pre-commit rejection retained a native dispatch ledger"
    );

    let replay = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(replay.reason.as_deref(), Some(COMPENSATED_REPLAY));
    assert!(replay.output.is_none());
    let replayed = custody(&fixture)?;
    assert_released(&replayed);
    assert_eq!(replayed.uses, Vec::<String>::new());
    assert!(!replayed.declassified_egress);
    assert!(!replayed.ledger);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_declassification_ledger_fault_after_consumption_remains_unconfirmed() -> TestResult {
    let (fixture, _) = profile(true, 300)?;
    let store = fixture.authority.admission_operation_store();
    store
        .inject_native_dispatch_ledger_failure_for_test(NativeDispatchLedgerTestFault::AfterRow)?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
    store.clear_native_dispatch_ledger_failure_for_test()?;
    let response = response?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(RECONCILIATION_REQUIRED));
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let after = custody(&fixture)?;
    // The declassified egress commit is durable; only the ledger write failed.
    assert_eq!(after.uses, ["consumed_pending_dispatch"]);
    assert!(after.declassified_egress);
    assert!(!after.ledger);
    assert_eq!(
        after.state,
        AdmissionOperationState::CapturePending,
        "consumed declassification authority was compensated as a clean pre-commit rejection"
    );
    assert_eq!(after.quota, (1, 0));
    assert_eq!(
        after.runtime,
        [RuntimeParticipantDisposition::ReservedBeforeDispatch]
    );
    assert_eq!(
        after.approval,
        [GovernedApprovalClaimDisposition::ReservedBeforeDispatch]
    );
    assert_eq!(
        after.dpop,
        [DpopReplayClaimDisposition::ReservedBeforeDispatch]
    );
    Ok(())
}
