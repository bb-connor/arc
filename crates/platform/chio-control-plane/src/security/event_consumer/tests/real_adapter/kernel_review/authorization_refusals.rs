use super::*;
use chio_kernel::{
    ActiveResponseAdmissionRequest, ActiveResponseAuthorizationRequest, KernelError,
};

fn signed_request(
    fixture: &RealAdapterFixture,
    capability: CapabilityToken,
    mut plan: chio_security_types::ResponsePlan,
    threshold_intent_hash: Option<&str>,
) -> ActiveResponseAdmissionRequest {
    let original = fixture.native_request();
    let capability_hash = authorization_capability_hash(&capability).test_unwrap();
    plan.operator_capability.capability_digest =
        crate::security::event_consumer::digest_from_canonical_hex(&capability_hash).test_unwrap();
    let canonical_plan = serde_json::to_value(plan.authorization_body()).test_unwrap();
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan).test_unwrap();
    plan.plan_hash =
        crate::security::event_consumer::digest_from_canonical_hex(&plan_body_hash).test_unwrap();
    let intent = GovernedTransactionIntent::active_response_plan(
        GovernedResponsePlanIntentBody::new(
            GOVERNED_RESPONSE_PLAN_SCHEMA,
            plan.action_id.as_str(),
            capability.id.clone(),
            capability_hash.clone(),
            capability.expires_at,
            capability.subject.clone(),
            canonical_plan,
            plan_body_hash.clone(),
            json!({"affectedSetHash": hex::encode(plan.affected_set_hash.as_bytes())}),
            vec![GovernedResponseEffect::ThrottleSession],
            plan.expires_at_unix_ms / 1_000,
            json!({"responsePlanHash": plan_body_hash}),
        )
        .test_unwrap(),
    );
    let intent_hash = intent.binding_hash().test_unwrap();
    let approval_hash = threshold_intent_hash.unwrap_or(&intent_hash);
    let mut proposal_body = original.threshold_proposal().test_unwrap().body().clone();
    proposal_body.governed_intent_hash = approval_hash.to_owned();
    proposal_body.authorizing_capability_digest = capability_hash;
    let proposal =
        ThresholdApprovalProposal::sign(proposal_body, &fixture.threshold_policy_authority)
            .test_unwrap();
    assert!(proposal.verify_integrity_embedded_key().test_unwrap());
    let approver = Keypair::from_seed(&[0x86_u8; 32]);
    let tokens: Vec<_> = original
        .approval_tokens()
        .iter()
        .map(|token| {
            let mut body = token.body();
            assert_eq!(body.approver, approver.public_key());
            body.governed_intent_hash = approval_hash.to_owned();
            body.threshold_proposal_hash = Some(proposal.proposal_hash().test_unwrap());
            GovernedApprovalToken::sign(body, &approver).test_unwrap()
        })
        .collect();
    let proof = real_adapter_submission_proof(&plan, &intent, &Keypair::from_seed(&[0x83_u8; 32]));
    let mut attestation = original.artifact_authority_attestation().body.clone();
    attestation.plan_body_hash = plan.plan_hash;
    attestation.governed_intent_hash =
        crate::security::event_consumer::digest_from_canonical_hex(&intent_hash).test_unwrap();
    attestation.submission_proof_digest =
        chio_kernel::active_response_submission_proof_digest(&proof).test_unwrap();
    let proposal = Some(proposal);
    attestation.artifact_payload_digest =
        chio_kernel::active_response_admission_artifact_payload_digest(
            &plan.authorization_body(),
            &capability,
            &intent,
            &proof,
            &proposal,
            &tokens,
        )
        .test_unwrap();
    let attestation = ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        attestation,
        &Ed25519Backend::new(fixture.submission_authority.clone()),
    )
    .test_unwrap();
    assert!(attestation.verify_integrity_embedded_key().test_unwrap());
    let authorization = ActiveResponseAuthorizationRequest::new(
        capability,
        plan.authorization_body(),
        intent,
        proof,
    )
    .test_unwrap();
    ActiveResponseAdmissionRequest::new(
        chio_security_types::FreshLiveAdmission::new(plan).test_unwrap(),
        authorization,
        original.admission_artifact_ref().clone(),
        attestation,
        proposal,
        tokens,
    )
    .test_unwrap()
}

fn assert_refused_without_mutation(
    fixture: &RealAdapterFixture,
    request: &ActiveResponseAdmissionRequest,
    expected: &str,
) {
    let before = real_adapter_mutation_snapshot(&fixture.paths);
    let budget_and_replay = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    let response_rows = || {
        [
            real_adapter_table_count(
                &fixture.paths.responses,
                "security_response_dispatch_fences",
            ),
            real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"),
            real_adapter_table_count(&fixture.paths.responses, "security_response_plans"),
            real_adapter_table_count(&fixture.paths.responses, "security_response_effects"),
        ]
    };
    let responses = response_rows();
    let result = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request);
    assert!(
        matches!(result, Err(KernelError::GovernedTransactionDenied(ref reason)) if reason == expected),
        "{result:?}"
    );
    assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), before);
    assert_eq!(
        real_adapter_budget_and_replay_snapshot(&fixture.paths),
        budget_and_replay
    );
    assert_eq!(response_rows(), responses);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn active_response_refuses_a_signed_capability_without_the_required_effect_grant() {
    let fixture = real_adapter_fixture();
    let original = fixture.native_request();
    fixture
        .runtime
        .kernel
        .verify_active_response_authorization(original.authorization())
        .test_unwrap();
    let mut capability = original.authorization().operator_capability().body();
    capability.scope.grants[0].tool_name =
        GovernedResponseEffect::RestrictEgress.tool_name().into();
    let capability = CapabilityToken::sign(capability, &fixture.operator_authority).test_unwrap();
    assert!(capability.verify_integrity_embedded_key().test_unwrap());
    let request = signed_request(&fixture, capability, original.response_plan().clone(), None);
    assert_refused_without_mutation(
        &fixture,
        &request,
        &format!("active-response authorization denied: verified capability lacks an exact unconditional Invoke grant for {} on {}",
            GovernedResponseEffect::ThrottleSession.tool_name(), ACTIVE_RESPONSE_SERVER_ID),
    );
}

#[test]
fn active_response_refuses_signed_approvals_bound_to_the_raw_plan_hash() {
    let fixture = real_adapter_fixture();
    let original = fixture.native_request();
    let raw_plan_hash = original
        .authorization()
        .submission_proof()
        .body
        .plan_body_hash
        .clone();
    let intent_hash = original
        .authorization()
        .governed_intent()
        .binding_hash()
        .test_unwrap();
    assert_ne!(raw_plan_hash, intent_hash);
    let request = signed_request(
        &fixture,
        original.authorization().operator_capability().clone(),
        original.response_plan().clone(),
        Some(&raw_plan_hash),
    );
    let verified = fixture
        .runtime
        .kernel
        .verify_active_response_authorization(request.authorization())
        .test_unwrap();
    assert_eq!(verified.governed_intent_hash(), intent_hash);
    assert_eq!(
        request
            .threshold_proposal()
            .test_unwrap()
            .body()
            .governed_intent_hash,
        raw_plan_hash
    );
    assert_refused_without_mutation(
        &fixture,
        &request,
        "active-response admission denied: threshold approval verification denied: threshold proposal does not match the request, capability, or active policy",
    );
}
