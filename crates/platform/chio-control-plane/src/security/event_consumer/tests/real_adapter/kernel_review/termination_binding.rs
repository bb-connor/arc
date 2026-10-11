//! An unrelated request must never terminate the actual durable preparation.
use super::*;
use chio_kernel::security_admission_operation::AdmissionDispatchState;
use chio_kernel::{
    ActiveResponseAdmissionRequest, ActiveResponseAuthorizationRequest, KernelError,
};

#[derive(Debug, PartialEq, Eq)]
struct PreparationSnapshot {
    operation: Option<AdmissionOperation>,
    approval: Option<ApprovalReservation>,
    cleanup: Vec<AdmissionCleanupAction>,
    budget_and_replay: [u64; 9],
    response_rows: [u64; 4],
}

fn snapshot(
    fixture: &RealAdapterFixture,
    prepared: &chio_kernel::PreparedActiveResponseAdmission,
) -> PreparationSnapshot {
    let (operation, approval, cleanup) = match prepared {
        chio_kernel::PreparedActiveResponseAdmission::Automatic(_) => (None, None, Vec::new()),
        chio_kernel::PreparedActiveResponseAdmission::Governed(reservation) => {
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
    PreparationSnapshot {
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

fn assert_unchanged(
    fixture: &RealAdapterFixture,
    prepared: &chio_kernel::PreparedActiveResponseAdmission,
    before: &PreparationSnapshot,
) {
    assert_eq!(&snapshot(fixture, prepared), before);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

fn request_with(
    request: &ActiveResponseAdmissionRequest,
    capability: CapabilityToken,
    tokens: Vec<GovernedApprovalToken>,
    attestation: ActiveResponseArtifactAuthorityAttestation,
) -> ActiveResponseAdmissionRequest {
    let authorization = ActiveResponseAuthorizationRequest::new(
        capability,
        request.authorization().plan_body().clone(),
        request.authorization().governed_intent().clone(),
        request.authorization().submission_proof().clone(),
    )
    .test_unwrap();
    ActiveResponseAdmissionRequest::new(
        chio_security_types::FreshLiveAdmission::new(request.response_plan().clone()).test_unwrap(),
        authorization,
        request.admission_artifact_ref().clone(),
        attestation,
        request.threshold_proposal().cloned(),
        tokens,
    )
    .test_unwrap()
}

fn foreign_revoked_request(fixture: &RealAdapterFixture) -> ActiveResponseAdmissionRequest {
    let request = fixture.native_request();
    let mut body = request.authorization().operator_capability().body();
    body.id = "foreign-revoked-active-response-capability".to_owned();
    let foreign = CapabilityToken::sign(body, &fixture.operator_authority).test_unwrap();
    assert_ne!(
        authorization_capability_hash(&foreign).test_unwrap(),
        authorization_capability_hash(request.authorization().operator_capability()).test_unwrap()
    );
    fixture
        .runtime
        .kernel
        .revoke_capability(&foreign.id)
        .test_unwrap();
    request_with(
        request,
        foreign,
        request.approval_tokens().to_vec(),
        request.artifact_authority_attestation().clone(),
    )
}

fn exercise_foreign_revoked_termination(governed: bool) {
    let fixture =
        real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::Live, governed);
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let foreign_request = foreign_revoked_request(&fixture);
    let before = snapshot(&fixture, &prepared);
    assert!(
        fixture
            .runtime
            .kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .get()
            < request
                .authorization()
                .submission_proof()
                .body
                .expires_at_unix_ms
    );

    let refused = fixture
        .runtime
        .kernel
        .terminate_never_committed_active_response(
            request.response_plan(),
            &binding,
            Some(&foreign_request),
        );

    // The Original fences the automatic dispatch or cancels the governed
    // reservation before returning Ok. An error-only assertion misses that.
    assert_unchanged(&fixture, &prepared, &before);
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "{refused:?}"
    );
    match &prepared {
        chio_kernel::PreparedActiveResponseAdmission::Automatic(_) => {
            // A fresh automatic preparation has a fresh authorization timestamp
            // and dispatch ID. Reconstruct the exact retained original instead.
            // This fixture's dispatch observer deliberately accepts governed
            // execution only; durable fence rows are checked above and below.
            let reconstructed = fixture
                .runtime
                .kernel
                .reconstruct_pre_dispatch_active_response_admission(request, &binding)
                .test_unwrap();
            let chio_kernel::PreDispatchActiveResponseReconstruction::Prepared(retry) =
                reconstructed
            else {
                panic!("the exact original automatic preparation was not retained");
            };
            assert_eq!(*retry, prepared);
            assert_eq!(
                retry
                    .durable_dispatch_binding(request.response_plan())
                    .test_unwrap(),
                binding
            );
            assert_unchanged(&fixture, &prepared, &before);
        }
        chio_kernel::PreparedActiveResponseAdmission::Governed(_) => {
            let retry = fixture
                .runtime
                .kernel
                .prepare_active_response_admission(request)
                .test_unwrap();
            assert_eq!(retry, prepared);
        }
    }
}

#[test]
fn terminate_foreign_revoked_capability_cannot_fence_automatic_preparation() {
    exercise_foreign_revoked_termination(false);
}

#[test]
fn terminate_foreign_revoked_capability_cannot_cancel_governed_approvals() {
    exercise_foreign_revoked_termination(true);
}

#[test]
fn commit_foreign_revoked_capability_cannot_cancel_the_actual_reservation() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let foreign_request = foreign_revoked_request(&fixture);
    let before = snapshot(&fixture, &prepared);

    let refused = fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(&foreign_request, &prepared);

    assert_unchanged(&fixture, &prepared, &before);
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "{refused:?}"
    );
    fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(request, &prepared)
        .test_unwrap();
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(operation_id(&prepared))
            .test_unwrap()
            .test_unwrap()
            .state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn terminate_extra_unsigned_expired_vote_cannot_cancel_the_verified_approval_set() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let mut tokens = request.approval_tokens().to_vec();
    let mut forged = tokens.first().test_unwrap().clone();
    forged.id = "unsigned-expired-extra-vote".to_owned();
    forged.expires_at = 0;
    assert!(!forged.verify_signature().test_unwrap());
    tokens.push(forged);
    let forged_request = request_with(
        request,
        request.authorization().operator_capability().clone(),
        tokens,
        request.artifact_authority_attestation().clone(),
    );
    let before = snapshot(&fixture, &prepared);

    let refused = fixture
        .runtime
        .kernel
        .terminate_never_committed_active_response(
            request.response_plan(),
            &binding,
            Some(&forged_request),
        );

    assert_unchanged(&fixture, &prepared, &before);
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "{refused:?}"
    );
    fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(request, &prepared)
        .test_unwrap();
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

fn request_with_a_different_signed_approval_set(
    fixture: &RealAdapterFixture,
) -> ActiveResponseAdmissionRequest {
    let request = fixture.native_request();
    let original = request.approval_tokens().first().test_unwrap();
    let mut body = original.body();
    body.id = "different-authentic-approval-token".to_owned();
    let approver = Keypair::from_seed(&[0x86_u8; 32]);
    assert_eq!(body.approver, approver.public_key());
    let different = GovernedApprovalToken::sign(body, &approver).test_unwrap();
    assert!(different.verify_signature().test_unwrap());
    assert_ne!(
        different.token_digest().test_unwrap(),
        original.token_digest().test_unwrap()
    );
    let tokens = vec![different];
    let mut attestation_body = request.artifact_authority_attestation().body.clone();
    attestation_body.artifact_payload_digest =
        chio_kernel::active_response_admission_artifact_payload_digest(
            request.authorization().plan_body(),
            request.authorization().operator_capability(),
            request.authorization().governed_intent(),
            request.authorization().submission_proof(),
            &request.threshold_proposal().cloned(),
            &tokens,
        )
        .test_unwrap();
    let attestation = ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        attestation_body,
        &Ed25519Backend::new(fixture.submission_authority.clone()),
    )
    .test_unwrap();
    request_with(
        request,
        request.authorization().operator_capability().clone(),
        tokens,
        attestation,
    )
}

#[test]
fn terminate_a_different_authentic_approval_set_cannot_cancel_the_original_set() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let different = request_with_a_different_signed_approval_set(&fixture);
    fixture
        .runtime
        .kernel
        .revoke_capability(&request.authorization().operator_capability().id)
        .test_unwrap();
    let before = snapshot(&fixture, &prepared);

    let refused = fixture
        .runtime
        .kernel
        .terminate_never_committed_active_response(
            request.response_plan(),
            &binding,
            Some(&different),
        );

    assert_unchanged(&fixture, &prepared, &before);
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "{refused:?}"
    );
    fixture
        .runtime
        .kernel
        .terminate_never_committed_active_response(request.response_plan(), &binding, Some(request))
        .test_unwrap();
    let operation = fixture
        .runtime
        .admission_operations
        .load(operation_id(&prepared))
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
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn terminate_exact_live_admission_refuses_without_mutating_the_preparation() {
    let fixture = real_adapter_fixture();
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let before = snapshot(&fixture, &prepared);

    let refused = fixture
        .runtime
        .kernel
        .terminate_never_committed_active_response(
            request.response_plan(),
            &binding,
            Some(request),
        );

    assert_unchanged(&fixture, &prepared, &before);
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(ref reason))
        if reason == "active-response admission denied: current live admission remains valid and cannot be terminated"),
        "{refused:?}"
    );
}

#[test]
fn terminate_exact_authenticated_submission_expiry_before_plan_expiry_remains_definitive() {
    for governed in [false, true] {
        let fixture = real_adapter_fixture_for_mode(
            chio_security_types::ResponseExecutionMode::Live,
            governed,
        );
        let request = fixture.native_request();
        let prepared = fixture
            .runtime
            .kernel
            .prepare_active_response_admission(request)
            .test_unwrap();
        let binding = prepared
            .durable_dispatch_binding(request.response_plan())
            .test_unwrap();
        let expires_at = request
            .authorization()
            .submission_proof()
            .body
            .expires_at_unix_ms;
        let _expired = chio_test_support::clock::scope_unix_secs(expires_at.div_ceil(1_000));
        let now = fixture
            .runtime
            .kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .get();
        assert!(expires_at <= now && now < request.response_plan().expires_at_unix_ms);

        fixture
            .runtime
            .kernel
            .terminate_never_committed_active_response(
                request.response_plan(),
                &binding,
                Some(request),
            )
            .test_unwrap();

        if governed {
            let id = operation_id(&prepared);
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
        } else {
            assert_eq!(
                real_adapter_table_count(
                    &fixture.paths.responses,
                    "security_response_dispatch_fences"
                ),
                1
            );
        }
        assert_eq!(fixture.runtime.executor.calls(), 0);
        assert_eq!(fixture.runtime.effects.executions(), 0);
    }
}
