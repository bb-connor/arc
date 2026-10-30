use super::*;
// HITL kernel-level flow tests.
//
// Shared fixtures are imported from the parent test module.

// Note: `GovernedApprovalDecision`, `GovernedApprovalToken`,
// `GovernedApprovalTokenBody`, and `Keypair` are already brought into
// paths intentionally resolve through `crate::approval*` so the test
// exercises the same type identities that downstream consumers see.

pub(super) struct FixedThresholdRequirement(pub(super) ThresholdApprovalRequirement);

impl ThresholdApprovalRequirementResolver for FixedThresholdRequirement {
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        _server_id: &str,
        _tool_name: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String> {
        Ok((policy_hash == self.0.policy_hash).then(|| self.0.clone()))
    }
}

pub(super) type CoreKeypair = Keypair;

pub(super) fn hitl_make_request() -> ToolCallRequest {
    let subject_kp = CoreKeypair::generate();
    let cap_builder_kernel = make_kernel(make_config());
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&cap_builder_kernel, &subject_kp, scope, 300);
    make_request("hitl-req-1", &cap, "read_file", "srv-a")
}

pub(super) fn hitl_sign_token(
    approver: &CoreKeypair,
    subject: &CoreKeypair,
    approval_id: &str,
    parameter_hash: &str,
    decision: GovernedApprovalDecision,
    now: u64,
) -> GovernedApprovalToken {
    let body = GovernedApprovalTokenBody {
        id: format!("tok-{approval_id}"),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: parameter_hash.to_string(),
        request_id: approval_id.to_string(),
        threshold_proposal_hash: None,
        issued_at: now.saturating_sub(10),
        expires_at: now + 600,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).unwrap()
}

fn bound_tool_invocation_fixture() -> (ChioKernel, ToolGrant, ToolCallRequest, u64) {
    let config = make_config();
    let approver = config.keypair.clone();
    let mut kernel = make_kernel(config);
    assert!(kernel
        .set_governed_approval_policy("test-tenant".into(), vec![approver.public_key()])
        .is_ok());
    let subject = CoreKeypair::generate();
    let mut grant = make_grant("srv-a", "read_file");
    grant
        .constraints
        .push(Constraint::RequireApprovalAbove { threshold_units: 0 });
    let capability = make_capability(&kernel, &subject, make_scope(vec![grant.clone()]), 300);
    let mut request = make_request_with_arguments(
        "bound-request-1",
        &capability,
        "read_file",
        "srv-a",
        serde_json::json!({"path": "/workspace/approved.txt", "options": {"limit": 10}}),
    );
    let mut intent = make_governed_intent(
        "bound-intent-1",
        "srv-a",
        "read_file",
        "read the approved file",
        0,
        "USD",
    );
    intent.body = GovernedTransactionIntentBody::BoundToolInvocation {
        capability_id: capability.id.clone(),
        parameters_hash: chio_core::sha256(&canonical_json_bytes(&request.arguments).unwrap()),
    };
    assert!(crate::approval::ToolApprovalContext::bind(
        &mut intent,
        &capability,
        &request.arguments,
        &request.request_id,
        &kernel.config.policy_hash,
        "test-tenant"
    )
    .is_ok());
    request.approval_token = Some(make_governed_approval_token(
        &approver,
        &capability.subject,
        &intent,
        &request.request_id,
    ));
    request.governed_intent = Some(intent);
    (kernel, grant, request, current_unix_timestamp())
}

#[test]
fn bound_tool_invocation_accepts_approved_canonical_arguments(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, grant, mut request, now) = bound_tool_invocation_fixture();
    let bound = kernel.bind_tool_approval_intent(&request)?;
    let serialized = serde_json::to_value(&bound)?;
    assert_eq!(
        serialized["context"]["chio_tool_approval"]["schema"],
        "chio.tool-approval-context.v1"
    );
    // Object member order does not change the RFC 8785 parameter binding.
    request.arguments =
        serde_json::from_str(r#"{"options":{"limit":10},"path":"/workspace/approved.txt"}"#)
            .unwrap();
    let result = kernel
        .validate_governed_transaction_pure(
            &request,
            &request.capability,
            &grant,
            GovernedValidationContext {
                parent_context: None,
                now,
            },
        )
        .unwrap();
    assert!(result.is_some());
    assert!(kernel
        .validate_governed_approval_for_dispatch_non_consuming(&request, &request.capability, now,)
        .unwrap()
        .is_some());
    Ok(())
}

#[test]
fn bound_tool_invocation_denies_parameter_mutation_with_valid_approval() {
    let (kernel, grant, original, now) = bound_tool_invocation_fixture();
    for arguments in [
        serde_json::json!({"path": "/workspace/forbidden.txt", "options": {"limit": 10}}),
        serde_json::json!({"path": "/workspace/approved.txt", "options": {"limit": 100}}),
        serde_json::json!({"path": "/workspace/approved.txt", "options": {"limit": 10}, "write": true}),
        serde_json::json!({"path": "/workspace/approved.txt", "options": {"limit": "10"}}),
        serde_json::json!({"path": "/workspace/approved.txt"}),
    ] {
        let mut request = original.clone();
        request.arguments = arguments;
        let error = kernel
            .validate_governed_transaction_pure(
                &request,
                &request.capability,
                &grant,
                GovernedValidationContext {
                    parent_context: None,
                    now,
                },
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("parameter hash does not match"),
            "{error}"
        );

        let direct_error = kernel
            .validate_governed_approval_for_dispatch_non_consuming(
                &request,
                &request.capability,
                now,
            )
            .unwrap_err();
        assert!(
            direct_error
                .to_string()
                .contains("parameter hash does not match"),
            "{direct_error}"
        );
    }
}

#[test]
fn bound_tool_invocation_denies_capability_transfer_for_same_subject() {
    let (kernel, grant, mut request, now) = bound_tool_invocation_fixture();
    let alternate = kernel
        .issue_capability(
            &request.capability.subject,
            make_scope(vec![grant.clone()]),
            300,
        )
        .unwrap();
    assert_ne!(alternate.id, request.capability.id);
    assert_eq!(alternate.subject, request.capability.subject);
    request.capability = alternate;

    let error = kernel
        .validate_governed_transaction_pure(
            &request,
            &request.capability,
            &grant,
            GovernedValidationContext {
                parent_context: None,
                now,
            },
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("capability does not match"),
        "{error}"
    );

    let direct_error = kernel
        .validate_governed_approval_for_dispatch_non_consuming(&request, &request.capability, now)
        .unwrap_err();
    assert!(
        direct_error
            .to_string()
            .contains("capability does not match"),
        "{direct_error}"
    );

    let intent_hash = request
        .governed_intent
        .as_ref()
        .unwrap()
        .binding_hash()
        .unwrap();
    let threshold_error = kernel
        .validate_threshold_approval_set(&request, &request.capability, &intent_hash, now)
        .unwrap_err();
    assert!(
        threshold_error
            .to_string()
            .contains("capability does not match"),
        "{threshold_error}"
    );
}

#[test]
fn bound_tool_invocation_rejects_mutation_before_approval_checks() {
    let (kernel, grant, mut request, now) = bound_tool_invocation_fixture();
    request.arguments = serde_json::json!({"path": "/workspace/forbidden.txt"});
    request.approval_token = None;
    let error = kernel
        .validate_governed_transaction_pure(
            &request,
            &request.capability,
            &grant,
            GovernedValidationContext {
                parent_context: None,
                now,
            },
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("parameter hash does not match"),
        "{error}"
    );

    let intent_hash = request
        .governed_intent
        .as_ref()
        .unwrap()
        .binding_hash()
        .unwrap();
    let threshold_error = kernel
        .validate_threshold_approval_set(&request, &request.capability, &intent_hash, now)
        .unwrap_err();
    assert!(
        threshold_error
            .to_string()
            .contains("parameter hash does not match"),
        "{threshold_error}"
    );
}

#[test]
fn threshold_approval_set_is_policy_bound_and_order_independent(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy_hash = sha256_hex(b"threshold-policy");
    let policy_authority = CoreKeypair::generate();
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let approver_c = CoreKeypair::generate();
    let mut config = make_config();
    config.policy_hash = policy_hash.clone();
    config.ca_public_keys.push(policy_authority.public_key());
    let mut kernel = make_kernel(config);
    let requirement = ThresholdApprovalRequirement::new(
        policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "alice".to_string(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "bob".to_string(),
                public_key: approver_b.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "carol".to_string(),
                public_key: approver_c.public_key(),
            },
        ],
        "directory-v1".to_string(),
        300,
    )
    .unwrap();
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement.clone(),
    )));

    let subject = CoreKeypair::generate();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-threshold", "transfer")]),
        600,
    );
    let intent = GovernedTransactionIntent {
        id: "intent-threshold-1".to_string(),
        server_id: "srv-threshold".to_string(),
        tool_name: "transfer".to_string(),
        purpose: "approve transfer".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: GovernedTransactionIntentBody::BoundToolInvocation {
            capability_id: cap.id.clone(),
            parameters_hash: chio_core::sha256(&canonical_json_bytes(
                &serde_json::json!({"path": "/app/src/main.rs"}),
            )?),
        },
    };
    let intent_hash = intent.binding_hash().unwrap();
    let now = current_unix_timestamp();
    let capability_digest = sha256_hex(&canonical_json_bytes(&cap).unwrap());
    let proposal_created_at = now.saturating_sub(5);
    let proposal_deadline = ThresholdApprovalProposalBody::proposal_deadline(
        proposal_created_at,
        requirement.timeout_seconds,
        cap.expires_at,
        None,
    )
    .unwrap();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "proposal-threshold-1".to_string(),
            request_id: "request-threshold-1".to_string(),
            governed_intent_hash: intent_hash.clone(),
            subject: cap.subject.clone(),
            authorizing_capability_digest: capability_digest,
            policy_hash,
            threshold: requirement.threshold,
            eligible_set_digest: requirement.eligible_set_digest.clone(),
            proposal_created_at,
            proposal_deadline,
            policy_authority: policy_authority.public_key(),
        },
        &policy_authority,
    )
    .unwrap();
    let proposal_hash = proposal.artifact_digest().unwrap();
    let make_token = |id: &str, approver: &CoreKeypair| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: cap.subject.clone(),
                governed_intent_hash: intent_hash.clone(),
                request_id: "request-threshold-1".to_string(),
                threshold_proposal_hash: Some(proposal_hash.clone()),
                issued_at: now,
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    };
    let token_a = make_token("token-a", &approver_a);
    let token_b = make_token("token-b", &approver_b);
    let mut request = make_request("request-threshold-1", &cap, "transfer", "srv-threshold");
    request.governed_intent = Some(intent);
    request.approval_tokens = vec![token_b.clone(), token_a.clone()];
    request.threshold_approval_proposal = Some(proposal.clone());
    let first_digest = request.approval_artifact_digest().unwrap();
    request.approval_tokens = vec![token_a, token_b];
    assert_eq!(first_digest, request.approval_artifact_digest().unwrap());

    let verified = kernel
        .validate_threshold_approval_set(&request, &cap, &intent_hash, now)
        .unwrap();
    assert_eq!(verified.body.threshold, 2);
    assert_eq!(verified.body.token_digests.len(), 2);

    let mut insufficient = request.clone();
    insufficient.approval_tokens.pop();
    let error = kernel
        .validate_threshold_approval_set(&insufficient, &cap, &intent_hash, now)
        .unwrap_err();
    assert!(error.to_string().contains("quorum"));

    let mut extended_proposal = proposal.body.clone();
    extended_proposal.proposal_deadline = extended_proposal.proposal_deadline.saturating_add(1);
    let extended_proposal =
        ThresholdApprovalProposal::sign(extended_proposal, &policy_authority).unwrap();
    let extended_hash = extended_proposal.artifact_digest().unwrap();
    let mut extended = request;
    extended.approval_tokens = [&approver_a, &approver_b]
        .into_iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("extended-token-{index}"),
                    approver: approver.public_key(),
                    subject: cap.subject.clone(),
                    governed_intent_hash: intent_hash.clone(),
                    request_id: "request-threshold-1".to_string(),
                    threshold_proposal_hash: Some(extended_hash.clone()),
                    issued_at: now,
                    expires_at: extended_proposal.body.proposal_deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        })
        .collect();
    extended.threshold_approval_proposal = Some(extended_proposal);
    let error = kernel
        .validate_threshold_approval_set(&extended, &cap, &intent_hash, now)
        .unwrap_err();
    assert!(error.to_string().contains("active policy"));
    Ok(())
}

// ---------------------------------------------------------------------
// (b) Approved resume produces an Approved outcome.
// ---------------------------------------------------------------------

#[test]
fn hitl_resume_approved_executes() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let approval = ApprovalRequest {
        approval_id: "ap-approve-1".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(subject.public_key()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hash.clone(),
        expires_at: 1_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "test".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    store.store_pending(&approval).unwrap();

    let token = hitl_sign_token(
        &approver,
        &subject,
        "ap-approve-1",
        &hash,
        GovernedApprovalDecision::Approved,
        600,
    );

    let decision = ApprovalDecision {
        approval_id: "ap-approve-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: Some("looks good".into()),
        approver: approver.public_key(),
        token,
        received_at: 600,
    };
    let outcome = resume_with_decision(&store, &decision, 600).unwrap();
    assert_eq!(outcome, ApprovalOutcome::Approved);

    // Pending record is gone; resolved record exists.
    assert!(store.get_pending("ap-approve-1").unwrap().is_none());
    assert!(store.get_resolution("ap-approve-1").unwrap().is_some());
    assert_eq!(
        store
            .count_approved(&request.agent_id, "policy-hitl")
            .unwrap(),
        1
    );
}

// ---------------------------------------------------------------------
// (c) Denied outcome records a denial and does not increment approvals.
// ---------------------------------------------------------------------

#[test]
fn hitl_resume_denied_records_denial() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let approval = ApprovalRequest {
        approval_id: "ap-deny-1".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(subject.public_key()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hash.clone(),
        expires_at: 1_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "test".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    store.store_pending(&approval).unwrap();

    let token = hitl_sign_token(
        &approver,
        &subject,
        "ap-deny-1",
        &hash,
        GovernedApprovalDecision::Denied,
        600,
    );
    let decision = ApprovalDecision {
        approval_id: "ap-deny-1".into(),
        outcome: ApprovalOutcome::Denied,
        reason: Some("not authorized".into()),
        approver: approver.public_key(),
        token,
        received_at: 700,
    };
    let outcome = resume_with_decision(&store, &decision, 700).unwrap();
    assert_eq!(outcome, ApprovalOutcome::Denied);

    // Approved counter stays zero.
    assert_eq!(
        store
            .count_approved(&request.agent_id, "policy-hitl")
            .unwrap(),
        0
    );
    // Resolution record is present with Denied outcome.
    let resolution = store.get_resolution("ap-deny-1").unwrap().unwrap();
    assert_eq!(resolution.outcome, ApprovalOutcome::Denied);
}

// ---------------------------------------------------------------------
// (d) Replay of a consumed approval token is rejected.
// ---------------------------------------------------------------------

#[test]
fn hitl_replay_of_consumed_token_rejected() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );
    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let approval = ApprovalRequest {
        approval_id: "ap-replay-1".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(subject.public_key()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hash.clone(),
        expires_at: 1_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "test".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    store.store_pending(&approval).unwrap();

    let token = hitl_sign_token(
        &approver,
        &subject,
        "ap-replay-1",
        &hash,
        GovernedApprovalDecision::Approved,
        600,
    );
    let decision = ApprovalDecision {
        approval_id: "ap-replay-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token: token.clone(),
        received_at: 600,
    };
    resume_with_decision(&store, &decision, 600).unwrap();

    // Re-submitting the same decision must fail. Because the pending
    // row has been removed, the error surface is "NotFound" wrapped as
    // ApprovalRejected by resume_with_decision's error mapping.
    let replay = resume_with_decision(&store, &decision, 605).unwrap_err();
    let msg = replay.to_string();
    assert!(
        msg.contains("approval rejected")
            || msg.contains("replay")
            || msg.contains("unknown approval"),
        "unexpected error: {msg}"
    );

    // Consumed registry records the token.
    assert!(store.is_consumed(&token.id, &hash).unwrap());

    // Re-storing the pending row and replaying the consumed token
    // should also fail with a replay error (the consumed registry is
    // authoritative even if the pending row reappears).
    let approval2 = ApprovalRequest {
        approval_id: "ap-replay-1".into(),
        ..approval
    };
    store.store_pending(&approval2).unwrap();
    let replay2 = resume_with_decision(&store, &decision, 610).unwrap_err();
    let msg2 = replay2.to_string();
    assert!(
        msg2.contains("replay") || msg2.contains("already"),
        "expected replay error, got: {msg2}"
    );
}

// Note: (e) Persistence-survives-restart is covered by the integration
// test in `crates/chio-store-sqlite/tests/approval_store.rs`, which
// owns both the SqliteApprovalStore and the kernel's resume path.
// Keeping that test out of the kernel's lib tests avoids the
// two-copies-of-chio-kernel dependency cycle (chio-store-sqlite depends
// on chio-kernel; the kernel's dev-deps cannot include chio-store-sqlite
// for use in lib tests without duplicating the crate).

// ---------------------------------------------------------------------
// (g) Batch respond applies multiple decisions at once.
// ---------------------------------------------------------------------

#[test]
fn hitl_batch_respond_applies_multiple_decisions() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let ids = ["ap-batch-1", "ap-batch-2", "ap-batch-3"];
    for id in &ids {
        let approval = ApprovalRequest {
            approval_id: (*id).into(),
            policy_id: "policy-batch".into(),
            subject_id: request.agent_id.clone(),
            capability_id: request.capability.id.clone(),
            subject_public_key: Some(subject.public_key()),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action: "invoke".into(),
            parameter_hash: hash.clone(),
            expires_at: 2_000_000,
            callback_hint: None,
            created_at: 500,
            summary: "batch".into(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        };
        store.store_pending(&approval).unwrap();
    }

    let decisions = [
        (
            ids[0],
            GovernedApprovalDecision::Approved,
            ApprovalOutcome::Approved,
        ),
        (
            ids[1],
            GovernedApprovalDecision::Denied,
            ApprovalOutcome::Denied,
        ),
        (
            ids[2],
            GovernedApprovalDecision::Approved,
            ApprovalOutcome::Approved,
        ),
    ];

    let mut approved = 0usize;
    let mut denied = 0usize;
    for (id, signed, envelope) in decisions {
        let token = hitl_sign_token(&approver, &subject, id, &hash, signed, 600);
        let decision = ApprovalDecision {
            approval_id: id.into(),
            outcome: envelope.clone(),
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 600,
        };
        let outcome = resume_with_decision(&store, &decision, 600).unwrap();
        assert_eq!(outcome, envelope);
        match outcome {
            ApprovalOutcome::Approved => approved += 1,
            ApprovalOutcome::Denied => denied += 1,
        }
    }
    assert_eq!(approved, 2);
    assert_eq!(denied, 1);
    assert_eq!(
        store
            .count_approved(&request.agent_id, "policy-batch")
            .unwrap(),
        2
    );
}

// ---------------------------------------------------------------------
// ApprovalToken.verify_against: signature, expiry, and binding guards.
// ---------------------------------------------------------------------

#[test]
fn hitl_token_verification_rejects_expired_tokens() {
    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "expired".into(),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: "h".into(),
        request_id: "a".into(),
        threshold_proposal_hash: None,
        issued_at: 10,
        expires_at: 20, // in the past relative to now=100
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign(body, &approver).unwrap();
    let req = ApprovalRequest {
        approval_id: "a".into(),
        policy_id: "p".into(),
        subject_id: "s".into(),
        capability_id: "c".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "tool".into(),
        action: "invoke".into(),
        parameter_hash: "h".into(),
        expires_at: 1000,
        callback_hint: None,
        created_at: 0,
        summary: String::new(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    let approval_token = ApprovalToken {
        approval_id: "a".into(),
        governed_token: token,
        approver: approver.public_key(),
    };
    let err = approval_token.verify_against(&req, 100).unwrap_err();
    assert!(err.to_string().contains("expired"));
}

#[test]
fn governed_approval_token_binds_every_authorization_field_and_time_window(
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        RequestId,
        IntentHash,
        Subject,
        Approver,
        Decision,
        IssuedAt,
        ExpiresAt,
    }

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "governed-token-binding".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "intent-hash".to_string(),
            request_id: "request-1".to_string(),
            threshold_proposal_hash: None,
            issued_at: 1_000,
            expires_at: 2_000,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )?;

    assert!(token.verify_integrity_embedded_key_at(1_500)?);

    for mutation in [
        Mutation::RequestId,
        Mutation::IntentHash,
        Mutation::Subject,
        Mutation::Approver,
        Mutation::Decision,
        Mutation::IssuedAt,
        Mutation::ExpiresAt,
    ] {
        let mut mutated = token.clone();
        match mutation {
            Mutation::RequestId => mutated.request_id = "request-2".to_string(),
            Mutation::IntentHash => {
                mutated.governed_intent_hash = "different-intent-hash".to_string();
            }
            Mutation::Subject => mutated.subject = CoreKeypair::generate().public_key(),
            Mutation::Approver => mutated.approver = CoreKeypair::generate().public_key(),
            Mutation::Decision => mutated.decision = GovernedApprovalDecision::Denied,
            Mutation::IssuedAt => mutated.issued_at = 999,
            Mutation::ExpiresAt => mutated.expires_at = 2_001,
        }
        assert!(
            matches!(mutated.verify_integrity_embedded_key_at(1_500), Ok(false)),
            "{mutation:?} mutation must invalidate the signature"
        );
    }

    let not_yet_valid = token.verify_integrity_embedded_key_at(999);
    assert!(
        not_yet_valid
            .as_ref()
            .is_err_and(|error| error.to_string().contains("not yet valid")),
        "unexpected not-yet-valid result: {not_yet_valid:?}"
    );
    let expired = token.verify_integrity_embedded_key_at(2_000);
    assert!(
        expired
            .as_ref()
            .is_err_and(|error| error.to_string().contains("expired")),
        "unexpected expiry result: {expired:?}"
    );

    Ok(())
}

#[test]
fn ap23_unbound_tool_approval_denies_before_dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, _, mut request, _) = bound_tool_invocation_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(
        super::dispatch_credentials::CountingDispatchServer {
            id: request.server_id.clone(),
            tool: request.tool_name.clone(),
            invocations: invocations.clone(),
        },
    ));
    let intent = request
        .governed_intent
        .as_mut()
        .ok_or("missing fixture intent")?;
    intent.body = GovernedTransactionIntentBody::ToolInvocation;
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &request.capability.subject,
        intent,
        &request.request_id,
    ));
    let result = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("bound tool invocation is required")),
        "{:?}",
        result.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn ap23_receipt_signer_has_no_implicit_approval_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut kernel, _, request, _) = bound_tool_invocation_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(
        super::dispatch_credentials::CountingDispatchServer {
            id: request.server_id.clone(),
            tool: request.tool_name.clone(),
            invocations: invocations.clone(),
        },
    ));
    kernel.set_governed_approval_policy("test-tenant".into(), Vec::new())?;
    let result = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("approval signer is not in configured roster")),
        "{:?}",
        result.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn ap23_roster_rejects_duplicate_and_weak_principals() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let key = CoreKeypair::generate().public_key();
    let duplicate = kernel.set_governed_approval_policy("tenant".into(), vec![key.clone(), key]);
    assert!(
        matches!(duplicate, Err(KernelError::GovernedTransactionDenied(ref reason)) if reason == "approval roster contains duplicate principals")
    );
    let weak = chio_core::PublicKey::from_hex(
        "0100000000000000000000000000000000000000000000000000000000000000",
    )?;
    let invalid = kernel.set_governed_approval_policy("tenant".into(), vec![weak]);
    assert!(
        matches!(invalid, Err(KernelError::GovernedTransactionDenied(ref reason)) if reason == "approval roster contains a weak signing key")
    );
    Ok(())
}
