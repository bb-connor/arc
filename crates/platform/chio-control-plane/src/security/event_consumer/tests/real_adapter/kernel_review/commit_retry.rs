//! Commit-time authority failures must preserve the exact durable preparation.
use super::*;
use chio_kernel::security_admission_operation::AdmissionDispatchState;
use chio_kernel::{InMemoryRevocationStore, KernelError, RevocationStore, RevocationStoreError};

const REVOCATION_READ_FAULT: &str = "injected active-response revocation read outage";

#[derive(Default)]
struct RevocationReadFault {
    inner: InMemoryRevocationStore,
    fail_next: AtomicBool,
}

impl RevocationStore for RevocationReadFault {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        if self.fail_next.swap(false, Ordering::AcqRel) {
            return Err(RevocationStoreError::Sync(REVOCATION_READ_FAULT.to_owned()));
        }
        self.inner.is_revoked(capability_id)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.inner.revoke(capability_id)
    }
}

#[test]
fn commit_revocation_read_outage_preserves_reserved_approvals_and_exact_retry() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request().clone();
    let RealAdapterRuntime {
        mut kernel,
        coordinator,
        admission_operations,
        approvals,
        effects,
        executor,
    } = fixture.runtime;
    drop(coordinator);
    let revocations = Arc::new(RevocationReadFault::default());
    Arc::get_mut(&mut kernel)
        .test_expect("exclusive fixture kernel")
        .set_revocation_store_handle(revocations.clone());
    let prepared = kernel
        .prepare_active_response_admission(&request)
        .test_unwrap();
    let id = operation_id(&prepared);
    let operation_before = admission_operations.load(id).test_unwrap().test_unwrap();
    let approval_before = approvals
        .get_approval_reservation(id)
        .test_unwrap()
        .test_unwrap();
    let cleanup_before = admission_operations.load_cleanup_actions(id).test_unwrap();
    let rows_before = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    assert_eq!(
        operation_before.state(),
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(
        operation_before.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(approval_before.state(), ReplayReservationState::Reserved);

    revocations.fail_next.store(true, Ordering::Release);
    let failed = kernel.commit_prepared_active_response_admission(&request, &prepared);

    // State is checked first: the Original must expose destructive compensation,
    // rather than passing merely because the authority read failed closed.
    assert_eq!(
        admission_operations.load(id).test_unwrap().as_ref(),
        Some(&operation_before),
        "a transient revocation read changed the reserved operation: {failed:?}"
    );
    assert_eq!(
        approvals.get_approval_reservation(id).test_unwrap(),
        Some(approval_before)
    );
    assert_eq!(
        admission_operations.load_cleanup_actions(id).test_unwrap(),
        cleanup_before
    );
    assert_eq!(
        real_adapter_budget_and_replay_snapshot(&fixture.paths),
        rows_before
    );
    assert_eq!(executor.calls(), 0);
    assert_eq!(effects.executions(), 0);
    assert!(
        matches!(failed, Err(KernelError::RevocationStore(RevocationStoreError::Sync(ref reason)))
            if reason == REVOCATION_READ_FAULT),
        "the global authority fault must retain its typed cause: {failed:?}"
    );

    kernel
        .commit_prepared_active_response_admission(&request, &prepared)
        .test_unwrap();
    let committed = admission_operations.load(id).test_unwrap().test_unwrap();
    assert!(committed.has_same_prepared_binding(&operation_before));
    assert_eq!(
        committed.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        committed.dispatch_state(),
        AdmissionDispatchState::Committed
    );
    assert_eq!(
        approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(executor.calls(), 0);
    assert_eq!(effects.executions(), 0);
}

#[test]
fn commit_actual_operator_revocation_compensates_the_reserved_operation() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request().clone();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(&request)
        .test_unwrap();
    let id = operation_id(&prepared);
    fixture
        .runtime
        .kernel
        .revoke_capability(&request.authorization().operator_capability().id)
        .test_unwrap();

    let denied = fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(&request, &prepared);

    assert!(
        matches!(denied, Err(KernelError::CapabilityRevoked(ref revoked_id))
        if revoked_id == &request.authorization().operator_capability().id),
        "{denied:?}"
    );
    let operation = fixture
        .runtime
        .admission_operations
        .load(id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn commit_immutable_plan_expiry_compensates_the_reserved_operation() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request().clone();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(&request)
        .test_unwrap();
    let id = operation_id(&prepared);
    let expired_at = request.response_plan().expires_at_unix_ms;
    let _expired = chio_test_support::clock::scope_unix_secs(expired_at.div_ceil(1_000));
    assert!(
        fixture
            .runtime
            .kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .get()
            >= expired_at
    );

    let denied = fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(&request, &prepared);

    assert!(
        matches!(denied, Err(KernelError::GovernedTransactionDenied(ref reason))
            if reason == "active-response authorization denied: compact response plan is not currently valid"),
        "{denied:?}"
    );
    let operation = fixture
        .runtime
        .admission_operations
        .load(id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}
