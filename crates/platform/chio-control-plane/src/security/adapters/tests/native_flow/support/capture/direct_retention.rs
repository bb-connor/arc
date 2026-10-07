// A host hook on the public retention path never reports committed egress
// custody as a clean pre-commit rejection.
use super::*;
use chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimDisposition;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantDisposition;
use chio_store_sqlite::admission_operation_store::NativeDispatchLedgerTestFault;

// The combined profile accepts its runtime report through epoch + 60s.
const RUNTIME_REPORT_EXPIRED_AT_MS: u64 = 60_001;
const RECONCILIATION_REQUIRED: &str = "security dispatch outcome requires reconciliation: security native dispatch capture callback failed; authoritative recovery required";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
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
        let (prepared, egress, ledger) =
            authority
                .prepare_egress()?
                .retain_for_capture(Some(deadline), grant_index, &policy)?;
        if egress.is_some_and(|history| history.commitment.is_some()) {
            self.committed_egress.fetch_add(1, Ordering::SeqCst);
        }
        if self.fault == Fault::RuntimeExpiredAfterRetention {
            let expired = now_ms().map_err(|error| KernelError::Internal(error.to_string()))?
                + RUNTIME_REPORT_EXPIRED_AT_MS;
            self.advance(expired)?;
        }
        authority.capture(prepared, &ledger, &policy).map(|_| ())
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
    });
    fixture.kernel.set_security_pre_dispatch_hook(hook.clone());
    Ok((fixture, hook))
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
