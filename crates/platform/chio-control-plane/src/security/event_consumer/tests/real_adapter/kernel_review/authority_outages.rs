//! Authority availability has a retryable class without weakening integrity.
use super::*;
use chio_kernel::{
    ActiveResponseExecutorAuthorityIdentity, ActiveResponseRequirementResolver, KernelError,
};
use chio_test_support::prelude::TestResultErr;

const OUTAGE: &str = "injected active-response authority outage";
const INTEGRITY: &str = "injected active-response authority integrity failure";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Healthy,
    FindingReadinessUnavailable,
    FindingLookupUnavailable,
    FindingReadinessIntegrity,
    FindingLookupIntegrity,
    PolicyUnavailable,
    PolicyInvalid,
    PolicyStale,
    ExecutorNotReady,
    ExecutorRejected,
}

type FaultControl = Arc<Mutex<Fault>>;

fn fault(control: &FaultControl) -> Fault {
    *control.lock().test_unwrap()
}

struct FindingFault {
    inner: Arc<dyn ActiveResponseFindingAuthority>,
    control: FaultControl,
}

impl ActiveResponseFindingAuthority for FindingFault {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        match fault(&self.control) {
            Fault::FindingReadinessUnavailable => Err(
                ActiveResponseFindingAuthorityError::Unavailable(OUTAGE.to_owned()),
            ),
            Fault::FindingReadinessIntegrity => Err(
                ActiveResponseFindingAuthorityError::Integrity(INTEGRITY.to_owned()),
            ),
            _ => self.inner.ensure_ready(),
        }
    }

    fn load_correlated_finding(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        match fault(&self.control) {
            Fault::FindingLookupUnavailable => Err(
                ActiveResponseFindingAuthorityError::Unavailable(OUTAGE.to_owned()),
            ),
            Fault::FindingLookupIntegrity => Err(ActiveResponseFindingAuthorityError::Integrity(
                INTEGRITY.to_owned(),
            )),
            _ => self.inner.load_correlated_finding(evidence_id),
        }
    }
}

struct PolicyFault {
    inner: Arc<dyn ActiveResponseRequirementResolver>,
    control: FaultControl,
}

impl ActiveResponseRequirementResolver for PolicyFault {
    fn resolve_active_response_requirement(
        &self,
        request: &chio_kernel::ActiveResponsePolicyRequest,
        policy_hash: &str,
    ) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError> {
        match fault(&self.control) {
            Fault::PolicyUnavailable => Err(ActiveResponsePolicyResolutionError::Unavailable(
                OUTAGE.to_owned(),
            )),
            Fault::PolicyInvalid => Err(ActiveResponsePolicyResolutionError::Invalid(
                INTEGRITY.to_owned(),
            )),
            Fault::PolicyStale => Err(ActiveResponsePolicyResolutionError::StalePolicy {
                expected: "different-policy".to_owned(),
                received: policy_hash.to_owned(),
            }),
            _ => self
                .inner
                .resolve_active_response_requirement(request, policy_hash),
        }
    }
}

struct ExecutorFault {
    inner: Arc<dyn ActiveResponseExecutorAuthority>,
    control: FaultControl,
}

impl ActiveResponseExecutorAuthority for ExecutorFault {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.inner.identity()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        match fault(&self.control) {
            Fault::ExecutorNotReady => {
                Err(ActiveResponseExecutorError::NotReady(OUTAGE.to_owned()))
            }
            Fault::ExecutorRejected => Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                INTEGRITY.to_owned(),
            )),
            _ => self.inner.ensure_ready(),
        }
    }

    fn claim_automatic_preparation(
        &self,
        response_plan: &chio_security_types::ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<PreparedActiveResponseDispatchBinding, ActiveResponseExecutorError> {
        self.inner
            .claim_automatic_preparation(response_plan, binding)
    }

    fn load_committed_active_response_dispatch(
        &self,
        tenant_id: &TenantId,
        dispatch_id: &RecordId,
    ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
        self.inner
            .load_committed_active_response_dispatch(tenant_id, dispatch_id)
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        response_plan: &chio_security_types::ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
        self.inner
            .fence_uncommitted_automatic_dispatch(response_plan, binding)
    }

    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<chio_kernel::ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        self.inner.execute_active_response(request)
    }
}

fn authority_fixture(control: &FaultControl) -> RealAdapterFixture {
    let finding = |inner| {
        Arc::new(FindingFault {
            inner,
            control: control.clone(),
        }) as Arc<dyn ActiveResponseFindingAuthority>
    };
    let policy = |inner| {
        Arc::new(PolicyFault {
            inner,
            control: control.clone(),
        }) as Arc<dyn ActiveResponseRequirementResolver>
    };
    let executor = |inner| {
        Arc::new(ExecutorFault {
            inner,
            control: control.clone(),
        }) as Arc<dyn ActiveResponseExecutorAuthority>
    };
    real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            finding_authority: Some(&finding),
            requirement_resolver: Some(&policy),
            executor_authority: Some(&executor),
            ..Default::default()
        },
    )
}

fn assert_no_admission_effect(fixture: &RealAdapterFixture, before: [u64; 9]) {
    assert_eq!(
        real_adapter_budget_and_replay_snapshot(&fixture.paths),
        before
    );
    assert_eq!(
        real_adapter_table_count(&fixture.paths.admission_operations, "admission_operations"),
        0
    );
    assert_eq!(
        real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"),
        0
    );
    assert_eq!(
        real_adapter_table_count(
            &fixture.paths.responses,
            "security_response_dispatch_fences"
        ),
        0
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

fn exercise_retryable_outage(selected: Fault) {
    let control = Arc::new(Mutex::new(Fault::Healthy));
    let fixture = authority_fixture(&control);
    let request = fixture.native_request();
    let before = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    *control.lock().test_unwrap() = selected;

    let kernel_result = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request);
    let port_result = fixture
        .runtime
        .coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone());

    assert_no_admission_effect(&fixture, before);
    assert!(
        matches!(kernel_result, Err(KernelError::Internal(ref reason)) if reason.contains(OUTAGE)),
        "{selected:?} acquired a definitive kernel denial: {kernel_result:?}"
    );
    let port_error = port_result.test_expect_err("outage must refuse preparation");
    assert_eq!(
        port_error.kind(),
        PortErrorKind::Unavailable,
        "{selected:?}: {port_error:?}"
    );
    assert_eq!(port_error.code().as_str(), "CHIO-KERNEL-INTERNAL");

    *control.lock().test_unwrap() = Fault::Healthy;
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let id = operation_id(&prepared);
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Reserved
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn finding_readiness_unavailable_remains_retryable_through_the_control_plane() {
    exercise_retryable_outage(Fault::FindingReadinessUnavailable);
}

#[test]
fn finding_lookup_unavailable_remains_retryable_through_the_control_plane() {
    exercise_retryable_outage(Fault::FindingLookupUnavailable);
}

#[test]
fn policy_unavailable_remains_retryable_through_the_control_plane() {
    exercise_retryable_outage(Fault::PolicyUnavailable);
}

#[test]
fn executor_not_ready_remains_retryable_through_the_control_plane() {
    exercise_retryable_outage(Fault::ExecutorNotReady);
}

#[test]
fn commit_authority_outages_preserve_the_exact_operation_approval_and_retry() {
    for selected in [
        Fault::FindingReadinessUnavailable,
        Fault::FindingLookupUnavailable,
        Fault::PolicyUnavailable,
        Fault::ExecutorNotReady,
    ] {
        let control = Arc::new(Mutex::new(Fault::Healthy));
        let fixture = authority_fixture(&control);
        let request = fixture.native_request();
        let prepared = fixture
            .runtime
            .kernel
            .prepare_active_response_admission(request)
            .test_unwrap();
        let id = operation_id(&prepared);
        let operation = fixture.runtime.admission_operations.load(id).test_unwrap();
        let approval = fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap();
        let cleanup = fixture
            .runtime
            .admission_operations
            .load_cleanup_actions(id)
            .test_unwrap();
        let before = real_adapter_budget_and_replay_snapshot(&fixture.paths);
        *control.lock().test_unwrap() = selected;

        let result = fixture
            .runtime
            .kernel
            .commit_prepared_active_response_admission(request, &prepared);

        assert_eq!(
            fixture.runtime.admission_operations.load(id).test_unwrap(),
            operation,
            "{selected:?} destroyed the reserved operation: {result:?}"
        );
        assert_eq!(
            fixture
                .runtime
                .approvals
                .get_approval_reservation(id)
                .test_unwrap(),
            approval
        );
        assert_eq!(
            fixture
                .runtime
                .admission_operations
                .load_cleanup_actions(id)
                .test_unwrap(),
            cleanup
        );
        assert_eq!(
            real_adapter_budget_and_replay_snapshot(&fixture.paths),
            before
        );
        assert_eq!(fixture.runtime.executor.calls(), 0);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert!(
            matches!(result, Err(KernelError::Internal(ref reason)) if reason.contains(OUTAGE)),
            "{selected:?}: {result:?}"
        );

        *control.lock().test_unwrap() = Fault::Healthy;
        fixture
            .runtime
            .kernel
            .commit_prepared_active_response_admission(request, &prepared)
            .test_unwrap();
        assert_eq!(
            fixture
                .runtime
                .admission_operations
                .load(id)
                .test_unwrap()
                .test_unwrap()
                .state(),
            AdmissionOperationState::DispatchCommitted
        );
        assert_eq!(
            fixture
                .runtime
                .approvals
                .get_approval_reservation(id)
                .test_unwrap()
                .test_unwrap()
                .state(),
            ReplayReservationState::Committed
        );
        assert_eq!(fixture.runtime.executor.calls(), 0);
        assert_eq!(fixture.runtime.effects.executions(), 0);
    }
}

#[test]
fn authority_integrity_stale_policy_and_explicit_rejection_remain_definitive() {
    for selected in [
        Fault::FindingReadinessIntegrity,
        Fault::FindingLookupIntegrity,
        Fault::PolicyInvalid,
        Fault::PolicyStale,
        Fault::ExecutorRejected,
    ] {
        let control = Arc::new(Mutex::new(Fault::Healthy));
        let fixture = authority_fixture(&control);
        let before = real_adapter_budget_and_replay_snapshot(&fixture.paths);
        *control.lock().test_unwrap() = selected;

        let kernel_result = fixture
            .runtime
            .kernel
            .prepare_active_response_admission(fixture.native_request());
        let port_result = fixture
            .runtime
            .coordinator
            .prepare_admission(&fixture.plan, fixture.artifacts.clone());

        assert_no_admission_effect(&fixture, before);
        assert!(
            matches!(
                kernel_result,
                Err(KernelError::GovernedTransactionDenied(_))
            ),
            "{selected:?}: {kernel_result:?}"
        );
        assert_eq!(
            port_result
                .test_expect_err("definitive authority rejection")
                .kind(),
            PortErrorKind::InvalidData,
            "{selected:?}"
        );
    }
}

#[test]
fn missing_finding_authority_is_an_unavailable_authority_in_pure_authorization() {
    let fixture = real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            publish_runtime: false,
            ..Default::default()
        },
    );
    let request = fixture.native_request().clone();
    let before = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    let RealAdapterRuntime {
        mut kernel,
        coordinator,
        executor,
        effects,
        ..
    } = fixture.runtime;
    drop(coordinator);
    Arc::get_mut(&mut kernel)
        .test_expect("exclusive unactivated kernel")
        .clear_active_response_finding_authority();

    let result = kernel.verify_active_response_authorization(request.authorization());

    assert!(
        matches!(result, Err(KernelError::Internal(ref reason)) if reason.contains("correlated-finding authority is not installed")),
        "{result:?}"
    );
    assert_eq!(
        real_adapter_budget_and_replay_snapshot(&fixture.paths),
        before
    );
    assert_eq!(executor.calls(), 0);
    assert_eq!(effects.executions(), 0);
}
