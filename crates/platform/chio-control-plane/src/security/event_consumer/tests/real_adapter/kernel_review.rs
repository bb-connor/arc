//! Kernel review regressions use real attested requests and durable stores.
use super::*;
use chio_kernel::approval::{
    ApprovalDecision, ApprovalFilter, ApprovalRequest, ApprovalReservation,
    ApprovalSetReservationInput, ApprovalStoreError, ApprovalStoreProfile, ResolvedApproval,
};
use chio_kernel::security_admission_operation::{
    AdmissionCleanupAction, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationError,
    AdmissionOperationStoreProfile,
};
use chio_test_support::prelude::TestResultOk;

struct AnchorReadFault {
    inner: Arc<SqliteSecurityAdmissionOperationStore>,
    fail_next: Arc<AtomicBool>,
}

impl AdmissionOperationStore for AnchorReadFault {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.inner.authority_profile()
    }
    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(self.inner.as_ref())
    }
    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.inner.create_prepared(operation)
    }
    fn load(&self, id: &str) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        self.inner.load(id)
    }
    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        authority: &str,
    ) -> Result<u64, AdmissionOperationError> {
        self.inner.count_unresolved_by_authority(kind, authority)
    }
    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        self.inner.compare_and_swap(request)
    }
    fn load_cleanup_actions(
        &self,
        id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        if self.fail_next.swap(false, Ordering::AcqRel) {
            return Err(AdmissionOperationError::Unavailable(
                "injected anchor read failure".into(),
            ));
        }
        self.inner.load_cleanup_actions(id)
    }
}

struct ApprovalReadFault {
    inner: Arc<SqliteApprovalStore>,
    fail_reserve: Arc<AtomicBool>,
    fail_readback: AtomicBool,
}

impl ApprovalStore for ApprovalReadFault {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        self.inner.authority_profile()
    }
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        self.inner.store_pending(request)
    }
    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        self.inner.get_pending(id)
    }
    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        self.inner.list_pending(filter)
    }
    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        self.inner.resolve(id, decision)
    }
    fn count_approved(&self, subject: &str, policy: &str) -> Result<u64, ApprovalStoreError> {
        self.inner.count_approved(subject, policy)
    }
    fn record_consumed(&self, token: &str, hash: &str, now: u64) -> Result<(), ApprovalStoreError> {
        self.inner.record_consumed(token, hash, now)
    }
    fn is_consumed(&self, token: &str, hash: &str) -> Result<bool, ApprovalStoreError> {
        self.inner.is_consumed(token, hash)
    }
    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        self.inner.get_resolution(id)
    }
    fn commit_approval_reservation(
        &self,
        id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.inner.commit_approval_reservation(id)
    }
    fn cancel_approval_reservation(
        &self,
        id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.inner.cancel_approval_reservation(id)
    }
    fn reserve_approval_set(
        &self,
        id: &str,
        set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        if self.fail_reserve.swap(false, Ordering::AcqRel) {
            // Reconciliation reads remain healthy until the failing write.
            self.fail_readback.store(true, Ordering::Release);
            return Err(ApprovalStoreError::Backend(
                "injected approval reservation failure".into(),
            ));
        }
        self.inner.reserve_approval_set(id, set)
    }
    fn get_approval_reservation(
        &self,
        id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        if self.fail_readback.swap(false, Ordering::AcqRel) {
            return Err(ApprovalStoreError::Backend(
                "injected approval readback failure".into(),
            ));
        }
        self.inner.get_approval_reservation(id)
    }
}

fn operation_id(prepared: &chio_kernel::PreparedActiveResponseAdmission) -> &str {
    let chio_kernel::PreparedActiveResponseAdmission::Governed(reservation) = prepared else {
        panic!("governed preparation required");
    };
    reservation.operation_id()
}

fn assert_retry_preserved(
    fixture: &RealAdapterFixture,
    prepared: &chio_kernel::PreparedActiveResponseAdmission,
    operation: &AdmissionOperation,
    approvals: &ApprovalReservation,
) {
    let id = operation_id(prepared);
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(id)
            .test_unwrap()
            .as_ref(),
        Some(operation)
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .as_ref(),
        Some(approvals)
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
    let retry = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(fixture.native_request())
        .test_expect("healthy preparation retry");
    assert_eq!(retry, *prepared);
}

#[test]
fn transient_anchor_read_cannot_compensate_an_existing_preparation() {
    let fault = Arc::new(AtomicBool::new(false));
    let decorate = |inner| {
        Arc::new(AnchorReadFault {
            inner,
            fail_next: fault.clone(),
        }) as Arc<dyn AdmissionOperationStore>
    };
    let fixture = real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            operations: Some(&decorate),
            ..Default::default()
        },
    );
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(fixture.native_request())
        .test_unwrap();
    let id = operation_id(&prepared);
    let operation = fixture
        .runtime
        .admission_operations
        .load(id)
        .test_unwrap()
        .test_unwrap();
    let approvals = fixture
        .runtime
        .approvals
        .get_approval_reservation(id)
        .test_unwrap()
        .test_unwrap();
    fault.store(true, Ordering::Release);
    assert!(matches!(
        fixture
            .runtime
            .kernel
            .prepare_active_response_admission(fixture.native_request()),
        Err(chio_kernel::KernelError::Internal(_))
    ));
    assert_retry_preserved(&fixture, &prepared, &operation, &approvals);
}

#[test]
fn transient_approval_readback_cannot_compensate_an_existing_preparation() {
    let fault = Arc::new(AtomicBool::new(false));
    let decorate = |inner| {
        Arc::new(ApprovalReadFault {
            inner,
            fail_reserve: fault.clone(),
            fail_readback: AtomicBool::new(false),
        }) as Arc<dyn ApprovalStore>
    };
    let fixture = real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            approvals: Some(&decorate),
            ..Default::default()
        },
    );
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(fixture.native_request())
        .test_unwrap();
    let id = operation_id(&prepared);
    let operation = fixture
        .runtime
        .admission_operations
        .load(id)
        .test_unwrap()
        .test_unwrap();
    let approvals = fixture
        .runtime
        .approvals
        .get_approval_reservation(id)
        .test_unwrap()
        .test_unwrap();
    fault.store(true, Ordering::Release);
    let failed = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(fixture.native_request());
    // Check durable state before the error classification so RED proves the
    // destructive branch, even though backend errors also need a retryable class.
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(id)
            .test_unwrap()
            .as_ref(),
        Some(&operation)
    );
    assert!(matches!(failed, Err(chio_kernel::KernelError::Internal(_))));
    assert_retry_preserved(&fixture, &prepared, &operation, &approvals);
}

fn assert_disabled<T: std::fmt::Debug>(result: Result<T, chio_kernel::KernelError>) {
    assert!(
        matches!(result, Err(chio_kernel::KernelError::GovernedTransactionDenied(ref reason)) if reason.contains("active-response plan support is disabled")),
        "{result:?}"
    );
}

#[test]
fn never_enabled_authorities_cannot_prepare_an_automatic_response() {
    let fixture = real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        false,
        RealAdapterFixtureOptions {
            publish_runtime: false,
            ..Default::default()
        },
    );
    let before = real_adapter_mutation_snapshot(&fixture.paths);
    assert_disabled(
        fixture
            .runtime
            .kernel
            .prepare_active_response_admission(fixture.native_request()),
    );
    assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), before);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn published_deactivation_blocks_prepare_commit_execute_and_resume() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request().clone();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(&request)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let operation = fixture
        .runtime
        .admission_operations
        .load(operation_id(&prepared))
        .test_unwrap()
        .test_unwrap();
    let approvals = fixture
        .runtime
        .approvals
        .get_approval_reservation(operation_id(&prepared))
        .test_unwrap()
        .test_unwrap();
    let before = fixture.runtime.kernel.governed_security_runtime_status();
    let RealAdapterRuntime {
        mut kernel,
        coordinator,
        admission_operations,
        approvals: approval_store,
        executor,
        effects,
    } = fixture.runtime;
    drop(coordinator);
    Arc::get_mut(&mut kernel)
        .test_expect("exclusive kernel")
        .deactivate_governed_active_response_plans();
    assert_disabled(kernel.prepare_active_response_admission(&request));
    assert_disabled(kernel.commit_prepared_active_response_admission(&request, &prepared));
    assert_disabled(kernel.execute_prepared_active_response(&request, &prepared));
    assert_disabled(kernel.reconstruct_pre_dispatch_active_response_admission(&request, &binding));
    assert_disabled(
        kernel.recover_committed_active_response(request.response_plan(), prepared.dispatch_id()),
    );
    assert_disabled(
        kernel.resume_dispatch_committed_active_response(request.response_plan(), &binding),
    );
    let mut expected_status = before;
    expected_status.active_response_enabled = false;
    assert_eq!(kernel.governed_security_runtime_status(), expected_status);
    assert_eq!(
        admission_operations
            .load(operation_id(&prepared))
            .test_unwrap()
            .as_ref(),
        Some(&operation)
    );
    assert_eq!(
        approval_store
            .get_approval_reservation(operation_id(&prepared))
            .test_unwrap()
            .as_ref(),
        Some(&approvals)
    );
    assert_eq!(executor.calls(), 0);
    assert_eq!(effects.executions(), 0);
}

#[test]
fn published_clear_methods_disable_without_replacing_authorities() {
    for clear in [
        ChioKernel::clear_active_response_requirement_resolver,
        ChioKernel::clear_active_response_executor_authority,
        ChioKernel::clear_active_response_finding_authority,
    ] {
        let fixture = real_adapter_fixture();
        let request = fixture.native_request().clone();
        let mut expected = fixture.runtime.kernel.governed_security_runtime_status();
        expected.active_response_enabled = false;
        let RealAdapterRuntime {
            mut kernel,
            coordinator,
            executor,
            effects,
            ..
        } = fixture.runtime;
        drop(coordinator);
        clear(Arc::get_mut(&mut kernel).test_expect("exclusive kernel"));
        assert_disabled(kernel.prepare_active_response_admission(&request));
        assert_eq!(kernel.governed_security_runtime_status(), expected);
        assert_eq!(executor.calls(), 0);
        assert_eq!(effects.executions(), 0);
    }
}

#[test]
fn deactivation_blocks_signed_simulation() {
    let fixture =
        real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::DryRun, false);
    let request = fixture
        .artifacts
        .clone()
        .into_simulation_request(fixture.plan.response_plan().clone())
        .test_unwrap();
    fixture
        .runtime
        .kernel
        .verify_active_response_simulation(&request)
        .test_expect("enabled signed simulation");
    let RealAdapterRuntime {
        mut kernel,
        coordinator,
        executor,
        effects,
        ..
    } = fixture.runtime;
    drop(coordinator);
    Arc::get_mut(&mut kernel)
        .test_expect("exclusive kernel")
        .deactivate_governed_active_response_plans();
    assert_disabled(kernel.verify_active_response_simulation(&request));
    assert_eq!(executor.calls(), 0);
    assert_eq!(effects.executions(), 0);
}

#[path = "kernel_review/operator_cancel.rs"]
mod operator_cancel;

#[path = "kernel_review/commit_retry.rs"]
mod commit_retry;

#[path = "kernel_review/termination_binding.rs"]
mod termination_binding;

#[path = "kernel_review/authority_outages.rs"]
mod authority_outages;

#[path = "kernel_review/active_response_residual.rs"]
mod active_response_residual;
