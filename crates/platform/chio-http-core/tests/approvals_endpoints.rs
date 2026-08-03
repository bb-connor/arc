//! End-to-end tests for the HITL HTTP handlers.
//!
//! Exercises the four substrate-independent handlers through an
//! `ApprovalAdmin` bound to an in-memory approval store. No HTTP
//! server is spun up: the `chio-http-core` crate is protocol-agnostic,
//! so the handlers are driven directly, mirroring the style of
//! `emergency_endpoints.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core_types::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    ThresholdApprovalRequirement,
};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_http_core::approvals::{
    handle_append_threshold_approval_vote, handle_batch_respond,
    handle_create_threshold_approval_proposal, handle_deliver_threshold_approval_response,
    handle_get_approval, handle_get_threshold_approval_proposal, handle_list_pending,
    handle_respond, AppendThresholdApprovalVoteRequest, ApprovalAdmin, ApprovalHandlerError,
    AuthenticatedThresholdApprovalRequestContext, BatchDecisionEntry, BatchRespondRequest,
    CreateThresholdApprovalProposalRequest, DeliverThresholdApprovalResponseRequest, PendingQuery,
    RespondRequest,
};
use chio_kernel::{
    ApprovalOutcome, ApprovalRequest, ApprovalStore, InMemoryApprovalStore,
    ThresholdApprovalCollectorStatus, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalCreationParameters,
};

fn make_admin() -> (ApprovalAdmin, Arc<InMemoryApprovalStore>) {
    let store = Arc::new(InMemoryApprovalStore::new());
    let admin = ApprovalAdmin::new(store.clone() as Arc<dyn ApprovalStore>);
    (admin, store)
}

fn store_pending(
    store: &InMemoryApprovalStore,
    id: &str,
    hash: &str,
    subject: &Keypair,
    trusted_approvers: &[chio_core_types::crypto::PublicKey],
) {
    let req = ApprovalRequest {
        approval_id: id.into(),
        policy_id: "p".into(),
        subject_id: "agent-1".into(),
        capability_id: "cap-1".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "tool".into(),
        action: "invoke".into(),
        parameter_hash: hash.into(),
        expires_at: 2_000_000,
        callback_hint: None,
        created_at: 100,
        summary: "e2e".into(),
        governed_intent: None,
        trusted_approvers: trusted_approvers.to_vec(),
        triggered_by: vec![],
    };
    store.store_pending(&req).unwrap();
}

fn sign_token(
    approver: &Keypair,
    subject: &Keypair,
    approval_id: &str,
    parameter_hash: &str,
    decision: GovernedApprovalDecision,
) -> GovernedApprovalToken {
    let body = GovernedApprovalTokenBody {
        id: format!("tok-{approval_id}"),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: parameter_hash.into(),
        threshold_proposal_hash: None,
        request_id: approval_id.into(),
        issued_at: 100,
        expires_at: 1000,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).unwrap()
}

#[test]
fn list_pending_returns_stored_approvals() {
    let (admin, store) = make_admin();
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    store_pending(&store, "a-2", "h-2", &subject, &[approver.public_key()]);

    let response = handle_list_pending(&admin, PendingQuery::default()).unwrap();
    assert_eq!(response.count, 2);
    assert_eq!(response.approvals.len(), 2);
}

#[test]
fn list_pending_respects_filters() {
    let (admin, store) = make_admin();
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    store_pending(&store, "a-2", "h-2", &subject, &[approver.public_key()]);

    let response = handle_list_pending(
        &admin,
        PendingQuery {
            tool_name: Some("missing".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(response.count, 0);
}

#[test]
fn get_approval_returns_pending_then_resolution() {
    let (admin, store) = make_admin();
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);

    let resp = handle_get_approval(&admin, "a-1").unwrap();
    assert!(resp.pending.is_some());
    assert!(resp.resolution.is_none());

    // Resolve and fetch again.
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: Some("approved".into()),
        approver: approver.public_key(),
        token,
    };
    handle_respond(&admin, "a-1", body, 500).unwrap();

    let resp = handle_get_approval(&admin, "a-1").unwrap();
    assert!(resp.pending.is_none());
    assert!(resp.resolution.is_some());
}

#[test]
fn get_approval_404_for_unknown_id() {
    let (admin, _) = make_admin();
    let err = handle_get_approval(&admin, "unknown").unwrap_err();
    assert_eq!(err.status(), 404);
    assert_eq!(err.code(), "not_found");
}

#[test]
fn respond_approves_pending_request() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: Some("OK".into()),
        approver: approver.public_key(),
        token,
    };
    let resp = handle_respond(&admin, "a-1", body, 500).unwrap();
    assert_eq!(resp.approval_id, "a-1");
    assert_eq!(resp.outcome, ApprovalOutcome::Approved);
    assert!(store.get_pending("a-1").unwrap().is_none());
}

#[test]
fn respond_rejects_mismatched_approval_id() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    // Token signed for a different approval id.
    let token = sign_token(
        &approver,
        &subject,
        "a-OTHER",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
    };
    let err = handle_respond(&admin, "a-1", body, 500).unwrap_err();
    assert_eq!(err.status(), 400);
    match err {
        ApprovalHandlerError::BadRequest(_) => {}
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn respond_rejects_replay() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token: token.clone(),
    };
    handle_respond(&admin, "a-1", body, 500).unwrap();

    // Store the pending row again and replay the same token.
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
    };
    let err = handle_respond(&admin, "a-1", body, 501).unwrap_err();
    match err {
        ApprovalHandlerError::ReplayDetected(_) => {}
        other => panic!("expected ReplayDetected, got {other:?}"),
    }
    assert_eq!(err.status(), 409);
}

#[test]
fn batch_respond_mixes_success_and_rejection() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    store_pending(&store, "a-2", "h-2", &subject, &[approver.public_key()]);
    let ok_token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    // This token's request_id doesn't match its envelope's approval_id
    // -- should be rejected per-entry but not fail the whole batch.
    let bad_token = sign_token(
        &approver,
        &subject,
        "a-MISMATCH",
        "h-2",
        GovernedApprovalDecision::Approved,
    );

    let body = BatchRespondRequest {
        decisions: vec![
            BatchDecisionEntry {
                approval_id: "a-1".into(),
                outcome: ApprovalOutcome::Approved,
                reason: None,
                approver: approver.public_key(),
                token: ok_token,
            },
            BatchDecisionEntry {
                approval_id: "a-2".into(),
                outcome: ApprovalOutcome::Approved,
                reason: None,
                approver: approver.public_key(),
                token: bad_token,
            },
        ],
    };
    let resp = handle_batch_respond(&admin, body, 500).unwrap();
    assert_eq!(resp.summary.total, 2);
    assert_eq!(resp.summary.approved, 1);
    assert_eq!(resp.summary.rejected, 1);
    let statuses: Vec<&str> = resp.results.iter().map(|r| r.status.as_str()).collect();
    assert!(statuses.contains(&"resolved"));
    assert!(statuses.contains(&"rejected"));
}

#[test]
fn batch_respond_empty_is_bad_request() {
    let (admin, _) = make_admin();
    let err =
        handle_batch_respond(&admin, BatchRespondRequest { decisions: vec![] }, 500).unwrap_err();
    assert_eq!(err.status(), 400);
}

#[test]
fn respond_rejects_untrusted_approver() {
    let (admin, store) = make_admin();
    let trusted_approver = Keypair::generate();
    let rogue_approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(
        &store,
        "a-1",
        "h-1",
        &subject,
        &[trusted_approver.public_key()],
    );

    let token = sign_token(
        &rogue_approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: rogue_approver.public_key(),
        token,
    };
    let err = handle_respond(&admin, "a-1", body, 500).unwrap_err();
    assert_eq!(err.status(), 403);
    match err {
        ApprovalHandlerError::Rejected(message) => {
            assert!(message.contains("not trusted"), "{message}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

struct ThresholdHttpFixture {
    policy_authority: Keypair,
    subject: Keypair,
    submitter: Keypair,
    second: Keypair,
    third: Keypair,
    requirement: ThresholdApprovalRequirement,
    policy_hash: String,
    intent_hash: String,
    proposal: ThresholdApprovalProposal,
}

impl ThresholdHttpFixture {
    fn new() -> Self {
        let policy_authority = Keypair::generate();
        let subject = Keypair::generate();
        let submitter = Keypair::generate();
        let second = Keypair::generate();
        let third = Keypair::generate();
        let eligible = BTreeMap::from([
            ("submitter".to_string(), submitter.public_key()),
            ("second".to_string(), second.public_key()),
            ("third".to_string(), third.public_key()),
        ]);
        let policy_hash = "ab".repeat(32);
        let intent_hash = "cd".repeat(32);
        let requirement =
            ThresholdApprovalRequirement::new(2, eligible, 100, policy_hash.clone(), 1).unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody::new(
                "proposal-http",
                "request-http",
                intent_hash.clone(),
                subject.public_key(),
                "ef".repeat(32),
                policy_hash.clone(),
                requirement.required(),
                requirement.eligible_set_digest(),
                100,
                requirement.proposal_timeout_seconds(),
                1_000,
                1_000,
            )
            .unwrap(),
            &policy_authority,
        )
        .unwrap();
        Self {
            policy_authority,
            subject,
            submitter,
            second,
            third,
            requirement,
            policy_hash,
            intent_hash,
            proposal,
        }
    }

    fn admin(&self) -> ApprovalAdmin {
        let store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let context = self.authenticated_context();
        let request_id = self.proposal.body().request_id().to_string();
        let policy_hash = self.policy_hash.clone();
        ApprovalAdmin::new_with_threshold_policy(
            store,
            self.policy_hash.clone(),
            vec![self.policy_authority.public_key()],
            Arc::new(move |received_request_id: &str, received_policy_hash: &str| {
                if received_request_id != request_id || received_policy_hash != policy_hash {
                    return Err(
                        chio_core_types::capability::threshold_approval::ThresholdApprovalResolutionError::Missing,
                    );
                }
                Ok(context.clone())
            }),
        )
        .unwrap()
    }

    fn authenticated_context(&self) -> AuthenticatedThresholdApprovalRequestContext {
        let matched_request = ThresholdApprovalRequest::new(
            self.proposal.body().request_id(),
            "payments",
            "transfer",
        )
        .unwrap();
        AuthenticatedThresholdApprovalRequestContext::new(
            matched_request.clone(),
            ThresholdApprovalProposalCreationContext::new(
                ThresholdApprovalProposalCreationParameters {
                    matched_request,
                    requirement: self.requirement.clone(),
                    subject: self.subject.public_key(),
                    governed_intent_hash: self.intent_hash.clone(),
                    authorization_capability_hash: "ef".repeat(32),
                    authorizing_capability_expires_at: 1_000,
                    governed_operation_expires_at: 1_000,
                    submitter: Some(self.submitter.public_key()),
                    separation_of_duties: true,
                },
            )
            .unwrap(),
        )
    }

    fn token(&self, id: &str, approver: &Keypair, issued_at: u64) -> GovernedApprovalToken {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: self.subject.public_key(),
                governed_intent_hash: self.intent_hash.clone(),
                threshold_proposal_hash: Some(self.proposal.proposal_hash().unwrap()),
                request_id: self.proposal.body().request_id().to_string(),
                issued_at,
                expires_at: 190,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    }
}

#[test]
fn threshold_handlers_collect_and_deliver_original_tokens() {
    let fixture = ThresholdHttpFixture::new();
    let admin = fixture.admin();
    let created = handle_create_threshold_approval_proposal(
        &admin,
        CreateThresholdApprovalProposalRequest {
            proposal: fixture.proposal.clone(),
        },
        105,
    )
    .unwrap();
    assert_eq!(
        created.proposal.status,
        ThresholdApprovalCollectorStatus::Collecting
    );

    let first = fixture.token("threshold-http-1", &fixture.second, 110);
    let second = fixture.token("threshold-http-2", &fixture.third, 112);
    let collecting = handle_append_threshold_approval_vote(
        &admin,
        fixture.proposal.body().proposal_id(),
        AppendThresholdApprovalVoteRequest {
            token: first.clone(),
        },
        111,
    )
    .unwrap();
    assert_eq!(
        collecting.proposal.status,
        ThresholdApprovalCollectorStatus::Collecting
    );
    let satisfied = handle_append_threshold_approval_vote(
        &admin,
        fixture.proposal.body().proposal_id(),
        AppendThresholdApprovalVoteRequest {
            token: second.clone(),
        },
        113,
    )
    .unwrap();
    assert_eq!(
        satisfied.proposal.status,
        ThresholdApprovalCollectorStatus::Satisfied
    );
    let pre_delivery = serde_json::to_string(&satisfied).unwrap();
    assert!(!pre_delivery.contains("threshold-http-1"));
    assert!(!pre_delivery.contains("threshold-http-2"));
    assert!(!pre_delivery.contains("signature"));

    let delivered = handle_deliver_threshold_approval_response(
        &admin,
        fixture.proposal.body().proposal_id(),
        DeliverThresholdApprovalResponseRequest {},
        114,
    )
    .unwrap();
    assert_eq!(delivered.approval_tokens, vec![first, second]);
    assert_eq!(
        delivered.proposal.status,
        ThresholdApprovalCollectorStatus::Delivered
    );
    let reopened =
        handle_get_threshold_approval_proposal(&admin, fixture.proposal.body().proposal_id(), 115)
            .unwrap();
    assert_eq!(reopened.proposal.delivered_at, Some(114));
}

#[test]
fn threshold_create_wire_shape_cannot_select_policy_or_separation_of_duties() {
    let fixture = ThresholdHttpFixture::new();
    let mut value = serde_json::to_value(CreateThresholdApprovalProposalRequest {
        proposal: fixture.proposal,
    })
    .unwrap();
    let object = value.as_object_mut().unwrap();
    object.insert("separationOfDuties".to_string(), serde_json::json!(false));
    object.insert(
        "submitter".to_string(),
        serde_json::json!(fixture.submitter.public_key()),
    );
    object.insert("server_id".to_string(), serde_json::json!("weaker-server"));
    object.insert("tool_name".to_string(), serde_json::json!("weaker-tool"));
    object.insert(
        "eligibleApprovers".to_string(),
        serde_json::json!({"attacker": PublicKey::from_hex(&"00".repeat(32)).ok()}),
    );
    assert!(serde_json::from_value::<CreateThresholdApprovalProposalRequest>(value).is_err());
}

#[test]
fn threshold_handlers_fail_closed_without_authenticated_policy_configuration() {
    let fixture = ThresholdHttpFixture::new();
    let (admin, _) = make_admin();
    let error = handle_create_threshold_approval_proposal(
        &admin,
        CreateThresholdApprovalProposalRequest {
            proposal: fixture.proposal,
        },
        105,
    )
    .unwrap_err();
    assert_eq!(error.status(), 500);
}

#[test]
fn threshold_get_rejects_changed_authenticated_context() {
    let fixture = ThresholdHttpFixture::new();
    let store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
    let context = Arc::new(RwLock::new(fixture.authenticated_context()));
    let resolved_context = Arc::clone(&context);
    let request_id = fixture.proposal.body().request_id().to_string();
    let policy_hash = fixture.policy_hash.clone();
    let admin = ApprovalAdmin::new_with_threshold_policy(
        store,
        fixture.policy_hash.clone(),
        vec![fixture.policy_authority.public_key()],
        Arc::new(move |received_request_id: &str, received_policy_hash: &str| {
            if received_request_id != request_id || received_policy_hash != policy_hash {
                return Err(
                    chio_core_types::capability::threshold_approval::ThresholdApprovalResolutionError::Missing,
                );
            }
            Ok(resolved_context.read().unwrap().clone())
        }),
    )
    .unwrap();
    handle_create_threshold_approval_proposal(
        &admin,
        CreateThresholdApprovalProposalRequest {
            proposal: fixture.proposal.clone(),
        },
        105,
    )
    .unwrap();
    let changed_route = ThresholdApprovalRequest::new(
        fixture.proposal.body().request_id(),
        "payments-v2",
        "transfer",
    )
    .unwrap();
    *context.write().unwrap() = AuthenticatedThresholdApprovalRequestContext::new(
        changed_route.clone(),
        ThresholdApprovalProposalCreationContext::new(
            ThresholdApprovalProposalCreationParameters {
                matched_request: changed_route,
                requirement: fixture.requirement.clone(),
                subject: fixture.subject.public_key(),
                governed_intent_hash: fixture.intent_hash.clone(),
                authorization_capability_hash: "ef".repeat(32),
                authorizing_capability_expires_at: 1_000,
                governed_operation_expires_at: 1_000,
                submitter: Some(fixture.submitter.public_key()),
                separation_of_duties: true,
            },
        )
        .unwrap(),
    );
    let error =
        handle_get_threshold_approval_proposal(&admin, fixture.proposal.body().proposal_id(), 106)
            .unwrap_err();
    assert_eq!(error.status(), 409);
}
