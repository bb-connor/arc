use super::*;
use chio_security_types::ports::ResponseDispatchApproval;

fn shorter_signed_request(
    fixture: &RealAdapterFixture,
    binding: &PreparedActiveResponseDispatchBinding,
) -> ActiveResponseAdmissionRequest {
    let original = fixture.native_request();
    let mut proof_body = original.authorization().submission_proof().body.clone();
    proof_body.expires_at_unix_ms = binding
        .authorized_at_unix_ms
        .checked_add(5_000)
        .test_unwrap();
    assert!(binding.authorized_at_unix_ms < proof_body.expires_at_unix_ms);
    assert!(
        proof_body.expires_at_unix_ms
            < original
                .authorization()
                .submission_proof()
                .body
                .expires_at_unix_ms
    );
    let submitter = Keypair::from_seed(&[0x83_u8; 32]);
    assert_eq!(proof_body.submitter, submitter.public_key());
    let proof = ActiveResponseSubmissionProof::sign_with_backend(
        proof_body,
        &Ed25519Backend::new(submitter),
    )
    .test_unwrap();
    assert!(proof.verify_signature().test_unwrap());
    assert_ne!(
        chio_kernel::active_response_submission_proof_digest(&proof).test_unwrap(),
        chio_kernel::active_response_submission_proof_digest(
            original.authorization().submission_proof()
        )
        .test_unwrap()
    );
    let artifact_ref =
        AdmissionArtifactRef::new("independent-shorter-signed-admission-artifact").test_unwrap();
    let mut attestation_body = original.artifact_authority_attestation().body.clone();
    attestation_body.artifact_ref = artifact_ref.clone();
    attestation_body.expires_at_unix_ms = proof.body.expires_at_unix_ms;
    attestation_body.submission_proof_digest =
        chio_kernel::active_response_submission_proof_digest(&proof).test_unwrap();
    attestation_body.artifact_payload_digest =
        chio_kernel::active_response_admission_artifact_payload_digest(
            original.authorization().plan_body(),
            original.authorization().operator_capability(),
            original.authorization().governed_intent(),
            &proof,
            &original.threshold_proposal().cloned(),
            original.approval_tokens(),
        )
        .test_unwrap();
    assert_ne!(
        attestation_body.artifact_payload_digest,
        original
            .artifact_authority_attestation()
            .body
            .artifact_payload_digest
    );
    let attestation = ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        attestation_body,
        &Ed25519Backend::new(fixture.submission_authority.clone()),
    )
    .test_unwrap();
    assert!(attestation.verify_signature().test_unwrap());
    let authorization = ActiveResponseAuthorizationRequest::new(
        original.authorization().operator_capability().clone(),
        original.authorization().plan_body().clone(),
        original.authorization().governed_intent().clone(),
        proof,
    )
    .test_unwrap();
    ActiveResponseAdmissionRequest::new(
        chio_security_types::FreshLiveAdmission::new(original.response_plan().clone())
            .test_unwrap(),
        authorization,
        artifact_ref,
        attestation,
        original.threshold_proposal().cloned(),
        original.approval_tokens().to_vec(),
    )
    .test_unwrap()
}

fn assert_same_semantic_binding(
    a: &PreparedActiveResponseDispatchBinding,
    b: &PreparedActiveResponseDispatchBinding,
) {
    assert_eq!(a.tenant_id, b.tenant_id);
    assert_eq!(a.action_id, b.action_id);
    assert_eq!(a.plan_hash, b.plan_hash);
    assert_eq!(
        a.authorization_capability_hash,
        b.authorization_capability_hash
    );
    assert_eq!(a.governed_intent_hash, b.governed_intent_hash);
    assert_eq!(a.policy_decision_hash, b.policy_decision_hash);
    assert_eq!(a.executor_authority_id, b.executor_authority_id);
    assert_eq!(
        a.executor_authority_generation,
        b.executor_authority_generation
    );
    match (&a.approval, &b.approval) {
        (ResponseDispatchApproval::Automatic, ResponseDispatchApproval::Automatic) => {}
        (
            ResponseDispatchApproval::Governed {
                approval_set_hash: a,
                ..
            },
            ResponseDispatchApproval::Governed {
                approval_set_hash: b,
                ..
            },
        ) => assert_eq!(a, b),
        _ => panic!("approval requirement changed between identical semantic requests"),
    }
}

fn prove_counterpart_was_admissible_at_recorded_time(
    fixture: &RealAdapterFixture,
    binding: &PreparedActiveResponseDispatchBinding,
    counterpart: &ActiveResponseAdmissionRequest,
) {
    let original = fixture.native_request();
    assert_eq!(original.response_plan(), counterpart.response_plan());
    assert_eq!(
        canonical_json_bytes(original.authorization().operator_capability()).test_unwrap(),
        canonical_json_bytes(counterpart.authorization().operator_capability()).test_unwrap()
    );
    assert_eq!(
        original.authorization().governed_intent(),
        counterpart.authorization().governed_intent()
    );
    assert_eq!(
        original.threshold_proposal(),
        counterpart.threshold_proposal()
    );
    assert_eq!(original.approval_tokens(), counterpart.approval_tokens());
    assert_eq!(
        fixture
            .runtime
            .kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .get(),
        binding.authorized_at_unix_ms
    );

    // A separate real kernel and durable stores admit the counterpart through
    // the complete production signature, artifact, policy and threshold path.
    // This is neither a forged unsigned expiry nor an artifact mismatch.
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let paths = RealAdapterPaths::in_directory(directory.path());
    let runtime = build_real_adapter_runtime(
        &paths,
        &fixture.operator_authority,
        &fixture.executor_signer,
        &fixture.submission_authority,
        &fixture.threshold_policy_authority,
        &fixture.threshold_requirement,
        &fixture.finding,
        original.response_plan(),
        Arc::clone(&fixture.clock),
        false,
    );
    let original_bindings = runtime
        .kernel
        .verify_active_response_authorization(original.authorization())
        .test_unwrap();
    let counterpart_bindings = runtime
        .kernel
        .verify_active_response_authorization(counterpart.authorization())
        .test_unwrap();
    assert_eq!(
        original_bindings.authorization_capability_hash(),
        counterpart_bindings.authorization_capability_hash()
    );
    assert_eq!(
        original_bindings.governed_intent_hash(),
        counterpart_bindings.governed_intent_hash()
    );
    assert_eq!(
        original_bindings.plan_body_hash(),
        counterpart_bindings.plan_body_hash()
    );
    assert_eq!(
        original_bindings.declared_approval_requirement(),
        counterpart_bindings.declared_approval_requirement()
    );
    assert_eq!(
        original_bindings.executor_subject(),
        counterpart_bindings.executor_subject()
    );
    assert_eq!(
        original_bindings.authenticated_submitter(),
        counterpart_bindings.authenticated_submitter()
    );
    let counterpart_prepared = runtime
        .kernel
        .prepare_active_response_admission(counterpart)
        .test_unwrap();
    let counterpart_binding = counterpart_prepared
        .durable_dispatch_binding(counterpart.response_plan())
        .test_unwrap();
    assert_eq!(
        counterpart_binding.authorized_at_unix_ms,
        binding.authorized_at_unix_ms
    );
    assert_same_semantic_binding(binding, &counterpart_binding);
    assert_eq!(runtime.executor.calls(), 0);
    assert_eq!(runtime.effects.executions(), 0);
}

fn exercise_shorter_signed_window(governed: bool, commit: bool) {
    let (_initial_time, fixture) = stable_fixture(governed);
    let original = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(original)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(original.response_plan())
        .test_unwrap();
    let counterpart = shorter_signed_request(&fixture, &binding);
    prove_counterpart_was_admissible_at_recorded_time(&fixture, &binding, &counterpart);
    let alternate_expiry = counterpart
        .authorization()
        .submission_proof()
        .body
        .expires_at_unix_ms;
    assert_eq!(alternate_expiry % 1_000, 0);
    let _expired_alternate = chio_test_support::clock::scope_unix_secs(alternate_expiry / 1_000);
    let now = fixture
        .runtime
        .kernel
        .authority_clock_reading()
        .test_unwrap()
        .unix_millis()
        .get();
    assert_eq!(now, alternate_expiry);
    assert!(
        now < original
            .authorization()
            .submission_proof()
            .body
            .expires_at_unix_ms
    );
    assert!(now < original.response_plan().expires_at_unix_ms);
    assert_original_reconstructs(&fixture, &prepared, &binding);
    let expired = fixture
        .runtime
        .kernel
        .verify_active_response_authorization(counterpart.authorization())
        .test_unwrap_err();
    assert!(
        matches!(expired, KernelError::GovernedTransactionDenied(ref reason)
        if reason == "active-response authorization denied: signed submission proof is outside the plan or current validity window"),
        "{expired:?}"
    );
    let before = retained_state(&fixture, &prepared);

    let refused = if commit {
        fixture
            .runtime
            .kernel
            .commit_prepared_active_response_admission(&counterpart, &prepared)
    } else {
        fixture
            .runtime
            .kernel
            .terminate_never_committed_active_response(
                original.response_plan(),
                &binding,
                Some(&counterpart),
            )
    };

    assert_eq!(retained_state(&fixture, &prepared), before,
        "a different genuine shorter-window artifact cancelled the admissible original: {refused:?}");
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "{refused:?}"
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
    assert_original_reconstructs(&fixture, &prepared, &binding);
    assert_eq!(retained_state(&fixture, &prepared), before);
}

#[test]
fn different_signed_shorter_artifact_cannot_compensate_original_governed_commit() {
    exercise_shorter_signed_window(true, true);
}

#[test]
fn different_signed_shorter_artifact_cannot_fence_original_automatic_dispatch() {
    exercise_shorter_signed_window(false, false);
}

#[test]
fn different_signed_shorter_artifact_cannot_terminate_original_governed_dispatch() {
    exercise_shorter_signed_window(true, false);
}

#[path = "artifact_identity/canonical_pin.rs"]
mod canonical_pin;
