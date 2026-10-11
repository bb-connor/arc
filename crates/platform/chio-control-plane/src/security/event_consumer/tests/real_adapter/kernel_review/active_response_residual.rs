//! Residuals use genuine signed evidence and retained durable preparations.
use super::*;
use chio_kernel::security_admission_operation::AdmissionDispatchState;
use chio_kernel::{
    ActiveResponseAdmissionRequest, ActiveResponseAuthorizationRequest,
    ActiveResponseExecutorAuthorityIdentity, KernelError, PreDispatchActiveResponseReconstruction,
    PreparedActiveResponseAdmission,
};
use chio_test_support::prelude::TestResultErr;

#[derive(Debug, PartialEq, Eq)]
struct RetainedState {
    operation: Option<AdmissionOperation>,
    approval: Option<ApprovalReservation>,
    cleanup: Vec<AdmissionCleanupAction>,
    budget_and_replay: [u64; 9],
    response_rows: [u64; 4],
}

fn retained_state(
    fixture: &RealAdapterFixture,
    prepared: &PreparedActiveResponseAdmission,
) -> RetainedState {
    let (operation, approval, cleanup) = match prepared {
        PreparedActiveResponseAdmission::Automatic(_) => (None, None, Vec::new()),
        PreparedActiveResponseAdmission::Governed(reservation) => {
            let id = reservation.operation_id();
            (
                fixture.runtime.admission_operations.load(id).test_unwrap(),
                fixture
                    .runtime
                    .approvals
                    .get_approval_reservation(id)
                    .test_unwrap(),
                fixture
                    .runtime
                    .admission_operations
                    .load_cleanup_actions(id)
                    .test_unwrap(),
            )
        }
    };
    RetainedState {
        operation,
        approval,
        cleanup,
        budget_and_replay: real_adapter_budget_and_replay_snapshot(&fixture.paths),
        response_rows: [
            real_adapter_table_count(
                &fixture.paths.responses,
                "security_response_dispatch_fences",
            ),
            real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"),
            real_adapter_table_count(&fixture.paths.responses, "security_response_plans"),
            real_adapter_table_count(&fixture.paths.responses, "security_response_effects"),
        ],
    }
}

fn stable_fixture(governed: bool) -> (chio_test_support::clock::ClockScope, RealAdapterFixture) {
    let seconds = real_adapter_now_unix_seconds()
        .checked_add(20)
        .test_unwrap();
    let scope = chio_test_support::clock::scope_unix_secs(seconds);
    let fixture =
        real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::Live, governed);
    assert_eq!(
        fixture
            .runtime
            .kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .get(),
        seconds * 1_000
    );
    assert!(
        seconds * 1_000
            < fixture
                .native_request()
                .authorization()
                .submission_proof()
                .body
                .expires_at_unix_ms
    );
    (scope, fixture)
}

fn assert_original_reconstructs(
    fixture: &RealAdapterFixture,
    prepared: &PreparedActiveResponseAdmission,
    binding: &PreparedActiveResponseDispatchBinding,
) {
    let reconstructed = fixture
        .runtime
        .kernel
        .reconstruct_pre_dispatch_active_response_admission(fixture.native_request(), binding)
        .test_unwrap();
    let PreDispatchActiveResponseReconstruction::Prepared(actual) = reconstructed else {
        panic!("the exact original preparation disappeared");
    };
    assert_eq!(actual.as_ref(), prepared);
    assert_eq!(
        actual
            .durable_dispatch_binding(fixture.native_request().response_plan())
            .test_unwrap(),
        *binding
    );
}

fn assert_compensated(fixture: &RealAdapterFixture, prepared: &PreparedActiveResponseAdmission) {
    let id = operation_id(prepared);
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

#[path = "active_response_residual/artifact_identity.rs"]
mod artifact_identity;
#[path = "active_response_residual/authority_windows.rs"]
mod authority_windows;
