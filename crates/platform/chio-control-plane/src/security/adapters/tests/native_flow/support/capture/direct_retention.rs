// A host hook on the public retention path never reports committed egress
// custody as a clean pre-commit rejection.
use super::*;
use chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimDisposition;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantDisposition;
use chio_store_sqlite::admission_operation_store::NativeDispatchLedgerTestFault;
use std::sync::Mutex;

// The combined profile accepts its runtime report through epoch + 60s.
const RUNTIME_REPORT_EXPIRED_AT_MS: u64 = 60_001;
const RECONCILIATION_REQUIRED: &str = "security dispatch outcome requires reconciliation: security native dispatch capture callback failed; authoritative recovery required";
const RUNTIME_EXPIRED: &str =
    "internal error: runtime pheromone policy revalidation failed: runtime_pheromone_advisory_stale";
const ALREADY_ATTEMPTED: &str =
    "durable admission failed: native capture authority already attempted capture";
const EGRESS_EXPIRED: &str =
    "durable admission failed: native egress deadline is expired or invalid";
const UNCONFIRMED_REPLAY: &str =
    "durable admission failed: native preparation requires original pre-budget authority";
const COMPENSATED_REPLAY: &str =
    "durable admission failed: request replay is retained in state CompensatedBeforeDispatch";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    Healthy,
    FenceExpiredBeforeRetention,
    RuntimeExpiredAfterRetention,
    LedgerAfterEgressCommit,
}

/// Plans with the real resolver, then retains and captures only through the
/// public kernel handles that any trusted host hook receives.
struct DirectHook {
    resolver: NativeFlowResolver,
    clock: Arc<FlowTestClock>,
    fault: Fault,
    committed_egress: AtomicUsize,
    outcomes: Mutex<Vec<String>>,
}

impl DirectHook {
    fn retain_and_capture(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        let planned = self
            .resolver
            .prepare_dispatch(authority.prepare_egress()?)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let policy = planned.policy_evidence().canonical_bytes().to_vec();
        let deadline = planned
            .admission()
            .egress_fence_plan
            .as_ref()
            .map(|plan| plan.expires_at_unix_ms)
            .ok_or_else(|| KernelError::Internal("direct hook requires an egress plan".into()))?;
        drop(planned);
        let grant_index = authority.grant_index()?;
        let spare = authority.prepare_egress()?;
        let retained = authority.prepare_egress()?;
        if self.fault == Fault::FenceExpiredBeforeRetention {
            self.advance(deadline)?;
        }
        let retention = retained.retain_for_capture(Some(deadline), grant_index, &policy);
        self.record(&retention)?;
        let (prepared, egress, ledger) = retention?;
        if egress.is_some_and(|history| history.commitment.is_some()) {
            self.committed_egress.fetch_add(1, Ordering::SeqCst);
        }
        if self.fault == Fault::RuntimeExpiredAfterRetention {
            let expired = now_ms().map_err(|error| KernelError::Internal(error.to_string()))?
                + RUNTIME_REPORT_EXPIRED_AT_MS;
            self.advance(expired)?;
        }
        let captured = authority.capture(prepared, &ledger, &policy).map(|_| ());
        self.record(&captured)?;
        if captured.is_err() {
            // The capture authority stays single use after a failed attempt.
            self.record(&authority.capture(spare, &ledger, &policy))?;
        }
        captured
    }

    fn record<T>(&self, result: &Result<T, KernelError>) -> Result<(), KernelError> {
        let outcome = match result {
            Ok(_) => "ok".to_owned(),
            Err(error) => error.to_string(),
        };
        self.outcomes
            .lock()
            .map_err(|_| KernelError::Internal("direct hook outcomes poisoned".into()))?
            .push(outcome);
        Ok(())
    }

    fn outcomes(&self) -> TestResult<Vec<String>> {
        Ok(self
            .outcomes
            .lock()
            .map_err(|_| "direct hook outcomes poisoned")?
            .clone())
    }

    fn advance(&self, unix_ms: u64) -> Result<(), KernelError> {
        self.clock
            .advance_to(unix_ms)
            .map_err(|error| KernelError::Internal(error.to_string()))
    }
}

impl SecurityPreDispatchHook for DirectHook {
    fn name(&self) -> &str {
        "native-direct-retention"
    }

    fn supports_native_dispatch(&self) -> bool {
        true
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }

    fn prepare_native_admission(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_admission(context, authority)
    }

    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_output(context, authority)
    }

    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        self.retain_and_capture(authority)
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "direct native retention reached legacy dispatch".into(),
        ))
    }
}

struct Custody {
    state: AdmissionOperationState,
    egress_committed: bool,
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
        .ok_or("original direct retention operation")?;
    let id = operation.binding().operation_id();
    let egress_committed = store
        .load_native_security_egress(id, &fence, now)?
        .ok_or("original egress operation")?
        .1
        .is_some_and(|history| history.commitment.is_some());
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
    let runtime = store
        .load_runtime_participant_history(id, &fence, now)?
        .map_or_else(Vec::new, |(_, history)| history);
    let approval = store
        .load_governed_approval_claim_history(id, &fence, now)?
        .map_or_else(Vec::new, |(_, history)| history);
    let dpop = store
        .load_dpop_replay_claim_history(id, &fence, now)?
        .map_or_else(Vec::new, |(_, history)| history);
    Ok(Custody {
        state: operation.state(),
        egress_committed,
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

fn arrange(fault: Fault) -> TestResult<(Fixture, Arc<DirectHook>)> {
    let mut fixture = Fixture::combined_native_credentials()?;
    let hook = Arc::new(DirectHook {
        resolver: NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(true, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            fixture.clock.clone(),
            flow_config(),
        )?,
        clock: fixture.clock.clone(),
        fault,
        committed_egress: AtomicUsize::new(0),
        outcomes: Mutex::new(Vec::new()),
    });
    fixture.kernel.set_security_pre_dispatch_hook(hook.clone());
    Ok((fixture, hook))
}

fn assert_released(custody: &Custody, fault: Fault) {
    assert_eq!(
        custody.state,
        AdmissionOperationState::CompensatedBeforeDispatch,
        "{fault:?}"
    );
    assert_eq!(custody.quota, (0, 0), "{fault:?}");
    assert_eq!(
        custody.runtime,
        [RuntimeParticipantDisposition::ReleasedBeforeDispatch],
        "{fault:?}"
    );
    assert_eq!(
        custody.approval,
        [GovernedApprovalClaimDisposition::ReleasedBeforeDispatch],
        "{fault:?}"
    );
    assert_eq!(
        custody.dpop,
        [DpopReplayClaimDisposition::ReleasedBeforeDispatch],
        "{fault:?}"
    );
}

fn committed_custody_stays_unconfirmed(fault: Fault, ledger: bool) -> TestResult {
    let (fixture, hook) = arrange(fault)?;
    let store = fixture.authority.admission_operation_store();
    if fault == Fault::LedgerAfterEgressCommit {
        store.inject_native_dispatch_ledger_failure_for_test(
            NativeDispatchLedgerTestFault::AfterRow,
        )?;
    }
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
    if fault == Fault::LedgerAfterEgressCommit {
        store.clear_native_dispatch_ledger_failure_for_test()?;
    }
    let response = response?;
    assert_eq!(response.verdict, Verdict::Deny, "{fault:?}");
    assert_eq!(
        response.reason.as_deref(),
        Some(RECONCILIATION_REQUIRED),
        "{fault:?}"
    );
    assert!(response.output.is_none(), "{fault:?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0, "{fault:?}");
    let after = custody(&fixture)?;
    // The public retention committed the egress fence before the failure.
    assert!(after.egress_committed, "{fault:?}");
    assert_eq!(after.ledger, ledger, "{fault:?}");
    if fault == Fault::RuntimeExpiredAfterRetention {
        assert_eq!(hook.committed_egress.load(Ordering::SeqCst), 1);
        assert_eq!(
            hook.outcomes()?,
            ["ok", RUNTIME_EXPIRED, ALREADY_ATTEMPTED],
            "{fault:?}"
        );
    }
    assert_eq!(
        after.state,
        AdmissionOperationState::CapturePending,
        "{fault:?}: committed egress custody was reported as a clean pre-commit rejection"
    );
    assert_eq!(after.quota, (1, 0), "{fault:?}");
    assert_eq!(
        after.runtime,
        [RuntimeParticipantDisposition::ReservedBeforeDispatch],
        "{fault:?}"
    );
    assert_eq!(
        after.approval,
        [GovernedApprovalClaimDisposition::ReservedBeforeDispatch],
        "{fault:?}"
    );
    assert_eq!(
        after.dpop,
        [DpopReplayClaimDisposition::ReservedBeforeDispatch],
        "{fault:?}"
    );

    // Recovery resolves the unconfirmed capture and keeps the committed fence.
    let replay = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{fault:?}");
    assert_eq!(
        replay.reason.as_deref(),
        Some(UNCONFIRMED_REPLAY),
        "{fault:?}"
    );
    assert!(replay.output.is_none(), "{fault:?}");
    let recovered = custody(&fixture)?;
    assert_released(&recovered, fault);
    assert!(recovered.egress_committed, "{fault:?}");
    assert_eq!(recovered.ledger, ledger, "{fault:?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0, "{fault:?}");
    Ok(())
}

#[test]
fn native_direct_retention_runtime_expiry_after_egress_commit_stays_unconfirmed() -> TestResult {
    committed_custody_stays_unconfirmed(Fault::RuntimeExpiredAfterRetention, true)
}

#[test]
fn native_direct_retention_ledger_fault_after_egress_commit_stays_unconfirmed() -> TestResult {
    committed_custody_stays_unconfirmed(Fault::LedgerAfterEgressCommit, false)
}

#[test]
fn native_direct_retention_fence_expiry_before_any_write_is_a_clean_rejection() -> TestResult {
    let fault = Fault::FenceExpiredBeforeRetention;
    let (fixture, hook) = arrange(fault)?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(RECONCILIATION_REQUIRED));
    assert!(response.output.is_none());
    assert_eq!(hook.outcomes()?, [EGRESS_EXPIRED]);
    assert_eq!(hook.committed_egress.load(Ordering::SeqCst), 0);
    let after = custody(&fixture)?;
    assert_released(&after, fault);
    assert!(!after.egress_committed);
    assert!(!after.ledger);
    let replay = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(replay.reason.as_deref(), Some(COMPENSATED_REPLAY));
    assert!(replay.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(hook.outcomes()?, [EGRESS_EXPIRED]);
    Ok(())
}

#[test]
fn native_direct_retention_healthy_capture_executes_once() -> TestResult {
    let (fixture, hook) = arrange(Fault::Healthy)?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(
        matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(hook.outcomes()?, ["ok", "ok"]);
    assert_eq!(hook.committed_egress.load(Ordering::SeqCst), 1);
    let after = custody(&fixture)?;
    assert_eq!(after.state, AdmissionOperationState::Completed);
    assert!(after.egress_committed);
    assert!(after.ledger);
    let replay = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&replay.receipt)?,
        chio_core::canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(hook.outcomes()?, ["ok", "ok"]);
    Ok(())
}
