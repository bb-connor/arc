use super::*;

// The authority wire types live in the unix-only authority module.
#[cfg(unix)]
#[test]
fn authority_artifact_draft_validator_rederives_all_static_bindings() {
    let fixture = real_adapter_fixture();
    let AttestedFindingAdmissionArtifactPayload::Kernel(payload) = &fixture.artifacts.payload
    else {
        panic!("real adapter fixture must carry kernel artifacts");
    };
    let response_plan = fixture.plan.response_plan();
    let draft = crate::security::ActiveResponseAdmissionArtifactsDraftWire {
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        admission_artifact_ref: payload.artifact_ref.clone(),
        operator_capability: payload.operator_capability.clone(),
        governed_intent: payload.governed_intent.clone(),
        submission_proof: payload.submission_proof.clone(),
        authority_attestation_body: payload.authority_attestation.body.clone(),
        threshold_proposal: payload.threshold_proposal.clone(),
        approval_tokens: crate::security::ActiveResponseApprovalTokens::new(
            payload.approval_tokens.clone(),
        )
        .unwrap_or_else(|error| panic!("bound approval tokens: {error}")),
    };
    crate::security::validate_active_response_artifacts_draft(
        response_plan,
        &payload.artifact_ref,
        &fixture.submission_authority.public_key(),
        &draft,
    )
    .unwrap_or_else(|error| panic!("validate exact authority draft: {error}"));

    let mut changed = draft;
    changed.authority_attestation_body.artifact_payload_digest = Digest32::new([0x71; 32]);
    assert!(crate::security::validate_active_response_artifacts_draft(
        response_plan,
        &payload.artifact_ref,
        &fixture.submission_authority.public_key(),
        &changed,
    )
    .is_err());
}
