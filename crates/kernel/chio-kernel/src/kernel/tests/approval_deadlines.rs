use super::*;

#[test]
fn inverted_signed_window_has_one_refusal_independent_of_verifier_time() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let approver = CoreKeypair::generate();
    let pending = ApprovalRequest {
        approval_id: "inverted".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(request.capability.subject.clone()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hitl_parameter_hash(&request),
        expires_at: 3690,
        callback_hint: None,
        created_at: 90,
        summary: "inverted window".into(),
        governed_intent: request.governed_intent.clone(),
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec!["force_approval".into()],
    };
    store.store_pending(&pending).unwrap();
    let token = ApprovalToken {
        approval_id: pending.approval_id.clone(),
        approver: approver.public_key(),
        governed_token: GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "inverted-token".into(),
                approver: approver.public_key(),
                subject: request.capability.subject.clone(),
                governed_intent_hash: pending.parameter_hash.clone(),
                request_id: pending.approval_id.clone(),
                threshold_proposal_hash: None,
                issued_at: 101,
                expires_at: 100,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )
        .unwrap(),
    };
    for now in [99, 100, 101] {
        let result = token.verify_against(&pending, now);
        assert!(
            matches!(result, Err(KernelError::ApprovalRejected(ref reason)) if reason == "approval token validity window is inverted"),
            "{result:?}"
        );
    }
    assert!(!store
        .is_consumed("inverted-token", &pending.parameter_hash)
        .unwrap());
}
