//! Integration tests for the SQLite HITL approval store.
//!
//! Exercises the store contract directly and simulates kernel restart
//! by opening a second store handle against the same database file. The
//! pending row, consumed-token registry, and resolved record must all
//! survive the restart.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    ThresholdApprovalRequirement,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel::{
    resume_with_decision, ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest,
    ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStore, ApprovalStoreError,
    ApprovalStoreProfile, ThresholdApprovalCollectorStatus,
    ThresholdApprovalProposalCreationContext, ThresholdApprovalProposalCreationParameters,
    ThresholdApprovalProposalRegistration,
};
use chio_store_sqlite::SqliteApprovalStore;

use chio_test_support::prelude::*;

fn unique_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn sample_request(id: &str, hash: &str) -> ApprovalRequest {
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    ApprovalRequest {
        approval_id: id.into(),
        policy_id: "policy-test".into(),
        subject_id: "agent-test".into(),
        capability_id: "cap-test".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "tool".into(),
        action: "invoke".into(),
        parameter_hash: hash.into(),
        expires_at: 2_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "sqlite contract".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    }
}

#[test]
fn approval_store_profile_reflects_instance_durability() {
    let memory = SqliteApprovalStore::open_in_memory().test_unwrap();
    assert_eq!(
        memory.authority_profile(),
        ApprovalStoreProfile::EphemeralLocal
    );

    let path = unique_path("chio-hitl-profile");
    let disk = SqliteApprovalStore::open(&path).test_unwrap();
    assert_eq!(
        disk.authority_profile(),
        ApprovalStoreProfile::SingleNodeDurable
    );
    assert!(SqliteApprovalStore::open(":memory:").is_err());
    assert!(SqliteApprovalStore::open("file::memory:?cache=shared").is_err());
    let _ = std::fs::remove_file(path);
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
        expires_at: 3600,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).test_unwrap()
}

struct ThresholdFixture {
    policy_authority: Keypair,
    subject: Keypair,
    submitter: Keypair,
    second: Keypair,
    third: Keypair,
    eligible: BTreeMap<String, PublicKey>,
    requirement: ThresholdApprovalRequirement,
    policy_hash: String,
    intent_hash: String,
    proposal: ThresholdApprovalProposal,
}

impl ThresholdFixture {
    fn new(proposal_id: &str, request_id: &str) -> Self {
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
            ThresholdApprovalRequirement::new(2, eligible.clone(), 100, policy_hash.clone(), 1)
                .test_unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody::new(
                proposal_id,
                request_id,
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
            .test_unwrap(),
            &policy_authority,
        )
        .test_unwrap();
        Self {
            policy_authority,
            subject,
            submitter,
            second,
            third,
            eligible,
            requirement,
            policy_hash,
            intent_hash,
            proposal,
        }
    }

    fn trusted(&self) -> Vec<PublicKey> {
        vec![self.policy_authority.public_key()]
    }

    fn registration(&self) -> ThresholdApprovalProposalRegistration {
        let context = self.creation_context();
        ThresholdApprovalProposalRegistration::new(
            self.proposal.clone(),
            &context,
            &self.trusted(),
            105,
        )
        .test_unwrap()
    }

    fn creation_context(&self) -> ThresholdApprovalProposalCreationContext {
        ThresholdApprovalProposalCreationContext::new(self.creation_parameters()).test_unwrap()
    }

    fn creation_parameters(&self) -> ThresholdApprovalProposalCreationParameters {
        ThresholdApprovalProposalCreationParameters {
            matched_request: ThresholdApprovalRequest::new(
                self.proposal.body().request_id(),
                "payments",
                "transfer",
            )
            .test_unwrap(),
            requirement: self.requirement.clone(),
            subject: self.subject.public_key(),
            governed_intent_hash: self.intent_hash.clone(),
            authorization_capability_hash: "ef".repeat(32),
            authorizing_capability_expires_at: 1_000,
            governed_operation_expires_at: 1_000,
            submitter: Some(self.submitter.public_key()),
            separation_of_duties: true,
        }
    }

    fn token(&self, id: &str, approver: &Keypair, issued_at: u64) -> GovernedApprovalToken {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: self.subject.public_key(),
                governed_intent_hash: self.intent_hash.clone(),
                threshold_proposal_hash: Some(self.proposal.proposal_hash().test_unwrap()),
                request_id: self.proposal.body().request_id().to_string(),
                issued_at,
                expires_at: 190,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_unwrap()
    }
}

#[test]
fn store_and_retrieve_round_trip() {
    let path = unique_path("chio-hitl-roundtrip");
    let store = SqliteApprovalStore::open(&path).test_unwrap();
    let r = sample_request("a-1", "h-1");
    store.store_pending(&r).test_unwrap();
    let fetched = store.get_pending("a-1").test_unwrap().test_unwrap();
    assert_eq!(fetched.approval_id, "a-1");
    let all = store.list_pending(&ApprovalFilter::default()).test_unwrap();
    assert_eq!(all.len(), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn filter_list_by_subject_and_server() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let mut r1 = sample_request("a-1", "h-1");
    r1.subject_id = "alice".into();
    let mut r2 = sample_request("a-2", "h-2");
    r2.subject_id = "bob".into();
    r2.tool_server = "payment".into();
    store.store_pending(&r1).test_unwrap();
    store.store_pending(&r2).test_unwrap();

    let alice = store
        .list_pending(&ApprovalFilter {
            subject_id: Some("alice".into()),
            ..Default::default()
        })
        .test_unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].approval_id, "a-1");

    let payment = store
        .list_pending(&ApprovalFilter {
            tool_server: Some("payment".into()),
            ..Default::default()
        })
        .test_unwrap();
    assert_eq!(payment.len(), 1);
    assert_eq!(payment[0].approval_id, "a-2");
}

#[test]
fn pending_filter_rejects_values_outside_sqlite_integer_range() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    store
        .store_pending(&sample_request("a-overflow", "h-overflow"))
        .test_unwrap();

    let timestamp_error = store
        .list_pending(&ApprovalFilter {
            not_expired_at: Some(u64::MAX),
            ..Default::default()
        })
        .test_unwrap_err();
    assert!(matches!(timestamp_error, ApprovalStoreError::Invalid(_)));
    assert!(timestamp_error
        .to_string()
        .contains("not_expired_at exceeds SQLite INTEGER range"));

    let limit_error = store
        .list_pending(&ApprovalFilter {
            limit: Some(usize::MAX),
            ..Default::default()
        })
        .test_unwrap_err();
    assert!(matches!(limit_error, ApprovalStoreError::Invalid(_)));
    assert!(limit_error
        .to_string()
        .contains("limit exceeds SQLite INTEGER range"));
}

#[test]
fn resolve_marks_approved_and_records_consumption() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let mut r = sample_request("a-1", "h-1");
    r.subject_public_key = Some(subject.public_key());
    r.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r).test_unwrap();

    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let decision = ApprovalDecision {
        approval_id: "a-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token: token.clone(),
        received_at: 1000,
    };

    store.resolve("a-1", &decision).test_unwrap();
    assert!(store.get_pending("a-1").test_unwrap().is_none());
    assert!(store.get_resolution("a-1").test_unwrap().is_some());
    assert!(store.is_consumed(&token.id, "h-1").test_unwrap());
    assert_eq!(
        store
            .count_approved("agent-test", "policy-test")
            .test_unwrap(),
        1
    );
}

#[test]
fn resolve_rejects_replay() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let mut r = sample_request("a-1", "h-1");
    r.subject_public_key = Some(subject.public_key());
    r.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r).test_unwrap();

    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let decision = ApprovalDecision {
        approval_id: "a-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
        received_at: 1000,
    };
    store.resolve("a-1", &decision).test_unwrap();

    // Re-insert the pending row and attempt to resolve again with the
    // same token. Must return a replay error.
    store.store_pending(&r).test_unwrap();
    let err = store.resolve("a-1", &decision).test_unwrap_err();
    match err {
        ApprovalStoreError::Replay(_) => {}
        other => panic!("expected Replay, got {other:?}"),
    }
}

#[test]
fn persistence_survives_restart() {
    let path = unique_path("chio-hitl-restart");
    let approver = Keypair::generate();
    let subject = Keypair::generate();

    // First "kernel" writes a pending approval.
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        let mut r = sample_request("ap-restart", "h-restart");
        r.subject_public_key = Some(subject.public_key());
        r.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&r).test_unwrap();
    }

    // Second "kernel" opens at the same path (simulating a restart).
    let store2 = SqliteApprovalStore::open(&path).test_unwrap();
    let pending = store2
        .list_pending(&ApprovalFilter::default())
        .test_unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].approval_id, "ap-restart");

    // Resume via the kernel's resume_with_decision now that the store
    // is re-opened; the approval must resolve cleanly.
    let token = sign_token(
        &approver,
        &subject,
        "ap-restart",
        "h-restart",
        GovernedApprovalDecision::Approved,
    );
    let decision = ApprovalDecision {
        approval_id: "ap-restart".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
        received_at: 1000,
    };
    let outcome = resume_with_decision(&store2, &decision, 1000).test_unwrap();
    assert_eq!(outcome, ApprovalOutcome::Approved);
    assert!(store2
        .list_pending(&ApprovalFilter::default())
        .test_unwrap()
        .is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn record_consumed_is_idempotent_on_first_write_only() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    store.record_consumed("tok-A", "hash-A", 1).test_unwrap();
    let err = store
        .record_consumed("tok-A", "hash-A", 2)
        .test_unwrap_err();
    match err {
        ApprovalStoreError::Replay(_) => {}
        other => panic!("expected Replay on second call, got {other:?}"),
    }
    assert!(store.is_consumed("tok-A", "hash-A").test_unwrap());
}

#[test]
fn count_approved_ignores_denied_rows() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let approver = Keypair::generate();
    let subject = Keypair::generate();

    let mut r_a = sample_request("r-a", "h-a");
    r_a.subject_id = "agent-x".into();
    r_a.policy_id = "policy-x".into();
    r_a.subject_public_key = Some(subject.public_key());
    r_a.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r_a).test_unwrap();
    let tok_a = sign_token(
        &approver,
        &subject,
        "r-a",
        "h-a",
        GovernedApprovalDecision::Approved,
    );
    store
        .resolve(
            "r-a",
            &ApprovalDecision {
                approval_id: "r-a".into(),
                outcome: ApprovalOutcome::Approved,
                reason: None,
                approver: approver.public_key(),
                token: tok_a,
                received_at: 10,
            },
        )
        .test_unwrap();

    let mut r_b = sample_request("r-b", "h-b");
    r_b.subject_id = "agent-x".into();
    r_b.policy_id = "policy-x".into();
    r_b.subject_public_key = Some(subject.public_key());
    r_b.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r_b).test_unwrap();
    let tok_b = sign_token(
        &approver,
        &subject,
        "r-b",
        "h-b",
        GovernedApprovalDecision::Denied,
    );
    store
        .resolve(
            "r-b",
            &ApprovalDecision {
                approval_id: "r-b".into(),
                outcome: ApprovalOutcome::Denied,
                reason: None,
                approver: approver.public_key(),
                token: tok_b,
                received_at: 11,
            },
        )
        .test_unwrap();

    assert_eq!(store.count_approved("agent-x", "policy-x").test_unwrap(), 1);
}

#[test]
fn threshold_collector_survives_every_reopen_boundary_and_delivers_original_tokens() {
    let path = unique_path("chio-threshold-collector-reopen");
    let fixture = ThresholdFixture::new("proposal-reopen", "request-reopen");
    let first = fixture.token("threshold-token-1", &fixture.second, 110);
    let second = fixture.token("threshold-token-2", &fixture.third, 112);
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        let created = store
            .create_threshold_approval_proposal(
                &fixture.registration(),
                &fixture.creation_context(),
                &fixture.trusted(),
                105,
            )
            .test_unwrap();
        assert_eq!(
            created.status(),
            ThresholdApprovalCollectorStatus::Collecting
        );
    }
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        let mut changed_parameters = fixture.creation_parameters();
        changed_parameters.matched_request = ThresholdApprovalRequest::new(
            fixture.proposal.body().request_id(),
            "payments-v2",
            "transfer",
        )
        .test_unwrap();
        let changed_context =
            ThresholdApprovalProposalCreationContext::new(changed_parameters).test_unwrap();
        assert!(matches!(
            store.get_threshold_approval_proposal(
                fixture.proposal.body().proposal_id(),
                &changed_context,
                &fixture.trusted(),
                109,
            ),
            Err(ApprovalStoreError::Conflict(_))
        ));
        let reopened = store
            .get_threshold_approval_proposal(
                fixture.proposal.body().proposal_id(),
                &fixture.creation_context(),
                &fixture.trusted(),
                109,
            )
            .test_unwrap()
            .test_unwrap();
        assert_eq!(reopened.proposal(), &fixture.proposal);
        let collecting = store
            .append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &first,
                &fixture.creation_context(),
                &fixture.trusted(),
                111,
            )
            .test_unwrap();
        assert_eq!(
            collecting.status(),
            ThresholdApprovalCollectorStatus::Collecting
        );
    }
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        let satisfied = store
            .append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &second,
                &fixture.creation_context(),
                &fixture.trusted(),
                113,
            )
            .test_unwrap();
        assert_eq!(
            satisfied.status(),
            ThresholdApprovalCollectorStatus::Satisfied
        );
        assert_eq!(
            satisfied.approval_tokens(),
            vec![first.clone(), second.clone()]
        );
    }
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        let delivered = store
            .mark_threshold_approval_response_delivered(
                fixture.proposal.body().proposal_id(),
                &fixture.creation_context(),
                &fixture.trusted(),
                114,
            )
            .test_unwrap();
        assert_eq!(
            delivered.status(),
            ThresholdApprovalCollectorStatus::Delivered
        );
        assert_eq!(
            delivered.approval_tokens(),
            vec![first.clone(), second.clone()]
        );
        let operation_id = "aa".repeat(32);
        let reservation = store
            .reserve_approval_set(&operation_id, &delivered.reservation_input().test_unwrap())
            .test_unwrap();
        assert_eq!(reservation.operation_id(), operation_id);
        let committed = store
            .commit_approval_reservation(&operation_id)
            .test_unwrap();
        assert_eq!(
            committed.state(),
            chio_kernel::ReplayReservationState::Committed
        );
    }
    let reopened = SqliteApprovalStore::open(&path).test_unwrap();
    let delivered = reopened
        .get_threshold_approval_proposal(
            fixture.proposal.body().proposal_id(),
            &fixture.creation_context(),
            &fixture.trusted(),
            300,
        )
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        delivered.status(),
        ThresholdApprovalCollectorStatus::Delivered
    );
    assert_eq!(delivered.delivered_at(), Some(114));
    assert!(reopened
        .get_approval_reservation(&"aa".repeat(32))
        .test_unwrap()
        .is_some());
    let _ = std::fs::remove_file(path);
}

#[test]
fn threshold_collector_rejects_sod_duplicates_stale_state_and_cross_registry_replay() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let fixture = ThresholdFixture::new("proposal-guards", "request-guards");
    store
        .create_threshold_approval_proposal(
            &fixture.registration(),
            &fixture.creation_context(),
            &fixture.trusted(),
            105,
        )
        .test_unwrap();

    let submitter = fixture.token("threshold-submitter", &fixture.submitter, 110);
    assert!(matches!(
        store.append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &submitter,
            &fixture.creation_context(),
            &fixture.trusted(),
            111,
        ),
        Err(ApprovalStoreError::Invalid(_))
    ));

    let first = fixture.token("threshold-guard-1", &fixture.second, 110);
    store
        .append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &first,
            &fixture.creation_context(),
            &fixture.trusted(),
            111,
        )
        .test_unwrap();

    let second_proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-cross-owner",
            "request-cross-owner",
            fixture.intent_hash.clone(),
            fixture.subject.public_key(),
            fixture
                .proposal
                .body()
                .authorization_capability_hash()
                .to_string(),
            fixture.policy_hash.clone(),
            fixture.requirement.required(),
            fixture.requirement.eligible_set_digest(),
            100,
            fixture.requirement.proposal_timeout_seconds(),
            1_000,
            1_000,
        )
        .test_unwrap(),
        &fixture.policy_authority,
    )
    .test_unwrap();
    let mut second_parameters = fixture.creation_parameters();
    second_parameters.matched_request =
        ThresholdApprovalRequest::new(second_proposal.body().request_id(), "payments", "transfer")
            .test_unwrap();
    second_parameters.authorization_capability_hash = fixture
        .proposal
        .body()
        .authorization_capability_hash()
        .to_string();
    let second_context =
        ThresholdApprovalProposalCreationContext::new(second_parameters).test_unwrap();
    let second_registration = ThresholdApprovalProposalRegistration::new(
        second_proposal.clone(),
        &second_context,
        &fixture.trusted(),
        105,
    )
    .test_unwrap();
    store
        .create_threshold_approval_proposal(
            &second_registration,
            &second_context,
            &fixture.trusted(),
            105,
        )
        .test_unwrap();
    let cross_proposal_same_id = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: first.id.clone(),
            approver: fixture.third.public_key(),
            subject: fixture.subject.public_key(),
            governed_intent_hash: fixture.intent_hash.clone(),
            threshold_proposal_hash: Some(second_proposal.proposal_hash().test_unwrap()),
            request_id: second_proposal.body().request_id().to_string(),
            issued_at: 112,
            expires_at: 190,
            decision: GovernedApprovalDecision::Approved,
        },
        &fixture.third,
    )
    .test_unwrap();
    assert!(matches!(
        store.append_threshold_approval_vote(
            second_proposal.body().proposal_id(),
            &cross_proposal_same_id,
            &second_context,
            &fixture.trusted(),
            113,
        ),
        Err(ApprovalStoreError::Replay(_))
    ));

    let same_request_changed_intent = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-request-rebind",
            fixture.proposal.body().request_id(),
            "09".repeat(32),
            fixture.subject.public_key(),
            fixture
                .proposal
                .body()
                .authorization_capability_hash()
                .to_string(),
            fixture.policy_hash.clone(),
            fixture.requirement.required(),
            fixture.requirement.eligible_set_digest(),
            100,
            fixture.requirement.proposal_timeout_seconds(),
            1_000,
            1_000,
        )
        .test_unwrap(),
        &fixture.policy_authority,
    )
    .test_unwrap();
    let mut changed_parameters = fixture.creation_parameters();
    changed_parameters.governed_intent_hash = "09".repeat(32);
    changed_parameters.authorization_capability_hash = fixture
        .proposal
        .body()
        .authorization_capability_hash()
        .to_string();
    let changed_context =
        ThresholdApprovalProposalCreationContext::new(changed_parameters).test_unwrap();
    let changed_registration = ThresholdApprovalProposalRegistration::new(
        same_request_changed_intent,
        &changed_context,
        &fixture.trusted(),
        105,
    )
    .test_unwrap();
    assert!(matches!(
        store.create_threshold_approval_proposal(
            &changed_registration,
            &changed_context,
            &fixture.trusted(),
            105,
        ),
        Err(ApprovalStoreError::Conflict(_))
    ));
    let duplicate_signer = fixture.token("threshold-guard-1b", &fixture.second, 112);
    assert!(matches!(
        store.append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &duplicate_signer,
            &fixture.creation_context(),
            &fixture.trusted(),
            113,
        ),
        Err(ApprovalStoreError::Replay(_))
    ));
    let stale_requirement =
        ThresholdApprovalRequirement::new(2, fixture.eligible.clone(), 100, "01".repeat(32), 2)
            .test_unwrap();
    let mut stale_policy_parameters = fixture.creation_parameters();
    stale_policy_parameters.requirement = stale_requirement;
    let stale_policy_context =
        ThresholdApprovalProposalCreationContext::new(stale_policy_parameters).test_unwrap();
    assert!(matches!(
        store.append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &fixture.token("threshold-guard-2", &fixture.third, 112),
            &stale_policy_context,
            &fixture.trusted(),
            113,
        ),
        Err(ApprovalStoreError::Conflict(_))
    ));
    assert!(matches!(
        store.append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &fixture.token("threshold-guard-2", &fixture.third, 112),
            &changed_context,
            &fixture.trusted(),
            113,
        ),
        Err(ApprovalStoreError::Conflict(_))
    ));
    assert!(matches!(
        store.get_threshold_approval_proposal(
            fixture.proposal.body().proposal_id(),
            &fixture.creation_context(),
            &[Keypair::generate().public_key()],
            113,
        ),
        Err(ApprovalStoreError::Invalid(_))
    ));

    let reservation = ApprovalSetReservationInput::new(
        "aa".repeat(32),
        vec![
            ApprovalReservationMember::new(first.id.clone(), first.token_digest().test_unwrap())
                .test_unwrap(),
        ],
        190,
    )
    .test_unwrap();
    assert!(matches!(
        store.reserve_approval_set(&"10".repeat(32), &reservation),
        Err(ApprovalStoreError::Replay(_))
    ));

    let second = fixture.token("threshold-guard-2", &fixture.third, 112);
    let satisfied = store
        .append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &second,
            &fixture.creation_context(),
            &fixture.trusted(),
            113,
        )
        .test_unwrap();
    assert_eq!(
        satisfied.status(),
        ThresholdApprovalCollectorStatus::Satisfied
    );
    let terminal_extra = fixture.token("threshold-terminal", &fixture.submitter, 114);
    assert!(matches!(
        store.append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &terminal_extra,
            &fixture.creation_context(),
            &fixture.trusted(),
            115,
        ),
        Err(ApprovalStoreError::AlreadyResolved(_))
    ));
}

#[test]
fn threshold_collector_persists_expiry_before_returning() {
    let path = unique_path("chio-threshold-expiry");
    let fixture = ThresholdFixture::new("proposal-expiry", "request-expiry");
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        store
            .create_threshold_approval_proposal(
                &fixture.registration(),
                &fixture.creation_context(),
                &fixture.trusted(),
                105,
            )
            .test_unwrap();
        let expired = store
            .get_threshold_approval_proposal(
                fixture.proposal.body().proposal_id(),
                &fixture.creation_context(),
                &fixture.trusted(),
                200,
            )
            .test_unwrap()
            .test_unwrap();
        assert_eq!(expired.status(), ThresholdApprovalCollectorStatus::Expired);
    }
    let reopened = SqliteApprovalStore::open(&path).test_unwrap();
    let expired = reopened
        .get_threshold_approval_proposal(
            fixture.proposal.body().proposal_id(),
            &fixture.creation_context(),
            &fixture.trusted(),
            201,
        )
        .test_unwrap()
        .test_unwrap();
    assert_eq!(expired.status(), ThresholdApprovalCollectorStatus::Expired);
    assert!(matches!(
        reopened.append_threshold_approval_vote(
            fixture.proposal.body().proposal_id(),
            &fixture.token("threshold-expired", &fixture.second, 110),
            &fixture.creation_context(),
            &fixture.trusted(),
            201,
        ),
        Err(ApprovalStoreError::AlreadyResolved(_))
    ));
    let _ = std::fs::remove_file(path);
}
