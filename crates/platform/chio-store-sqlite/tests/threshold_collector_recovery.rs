//! The durable collector rejects inconsistent snapshots before delivery or updates.

use std::sync::{Arc, Barrier};

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::crypto::{sha256_hex, Keypair, SigningAlgorithm};
use chio_kernel::{
    ThresholdApprovalCollector, ThresholdApprovalCollectorProposal,
    ThresholdApprovalCollectorState, ThresholdApprovalCollectorStore,
    ThresholdApprovalCollectorStoreError,
};
use chio_store_sqlite::SqliteApprovalStore;
use rusqlite::Connection;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    directory: tempfile::TempDir,
    authority: Keypair,
    initial: ThresholdApprovalCollectorProposal,
    vote: GovernedApprovalToken,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let authority = Keypair::generate();
        let approver = Keypair::generate();
        let requirement = ThresholdApprovalRequirement::new(
            sha256_hex(b"policy"),
            1,
            vec![ThresholdApproverIdentity {
                identifier: "approver".into(),
                public_key: approver.public_key(),
            }],
            "directory-v1".into(),
            100,
        )?;
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
                proposal_id: "proposal-1".into(),
                request_id: "request-1".into(),
                governed_intent_hash: sha256_hex(b"intent"),
                subject: Keypair::generate().public_key(),
                authorizing_capability_digest: sha256_hex(b"capability"),
                policy_hash: requirement.policy_hash.clone(),
                threshold: 1,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: authority.public_key(),
            },
            &authority,
        )?;
        let vote = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "vote-1".into(),
                approver: approver.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest()?),
                issued_at: 101,
                expires_at: 199,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )?;
        let store = Arc::new(SqliteApprovalStore::open(
            directory.path().join("approvals.db"),
        )?);
        let collector = ThresholdApprovalCollector::new(
            store,
            sha256_hex(b"policy"),
            vec![authority.public_key()],
        );
        let initial = collector.create_proposal(proposal, requirement, None, false, 100)?;
        collector.submit_token("proposal-1", vote.clone(), 110)?;
        Ok(Self {
            directory,
            authority,
            initial,
            vote,
        })
    }

    fn connection(&self) -> TestResult<Connection> {
        Ok(Connection::open(
            self.directory.path().join("approvals.db"),
        )?)
    }

    fn reopen(&self) -> TestResult<(Arc<SqliteApprovalStore>, ThresholdApprovalCollector)> {
        let store = Arc::new(SqliteApprovalStore::open(
            self.directory.path().join("approvals.db"),
        )?);
        let collector = ThresholdApprovalCollector::new(
            store.clone(),
            sha256_hex(b"policy"),
            vec![self.authority.public_key()],
        );
        Ok((store, collector))
    }

    fn assert_rejected_without_writes(&self) -> TestResult {
        let conn = self.connection()?;
        let before: Vec<u8> = conn.query_row(
            "SELECT record_json FROM chio_threshold_approval_collectors",
            [],
            |row| row.get(0),
        )?;
        let (store, collector) = self.reopen()?;
        assert!(store.get("proposal-1").is_err());
        assert!(collector.get_proposal("proposal-1").is_err());
        assert!(collector.deliver("proposal-1", 120).is_err());
        assert!(collector.cancel("proposal-1", 120).is_err());
        assert!(store
            .append_token(
                "proposal-1",
                1,
                &self.vote,
                Some("vote-1"),
                ThresholdApprovalCollectorState::Ready,
                120,
            )
            .is_err());
        assert!(store
            .transition(
                "proposal-1",
                1,
                ThresholdApprovalCollectorState::Delivered,
                120,
            )
            .is_err());
        let after: Vec<u8> = conn.query_row(
            "SELECT record_json FROM chio_threshold_approval_collectors",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(before, after);
        Ok(())
    }
}

#[test]
fn recovery_rejects_index_and_aggregate_disagreement() -> TestResult {
    for mutation in [
        "UPDATE chio_threshold_approval_collectors SET request_id = 'different-request'",
        "UPDATE chio_threshold_approval_collectors SET policy_hash = 'different-policy'",
        "UPDATE chio_threshold_approval_collectors SET state = 'collecting'",
        "UPDATE chio_threshold_approval_collectors SET version = 9",
        "UPDATE chio_threshold_approval_collectors SET updated_at = 109",
        "UPDATE chio_threshold_approval_collectors SET updated_at = -1",
        "UPDATE chio_threshold_approval_collectors SET submitter_fingerprint = 'different-submitter'",
        "UPDATE chio_threshold_approval_collectors SET proposal_json = x'7b7d'",
        "UPDATE chio_threshold_approval_collectors SET requirement_json = x'7b7d'",
    ] {
        let fixture = Fixture::new()?;
        assert_eq!(fixture.connection()?.execute(mutation, [])?, 1);
        fixture.assert_rejected_without_writes()?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_missing_or_rebound_vote_rows() -> TestResult {
    for mutation in [
        "DELETE FROM chio_threshold_approval_collector_votes",
        "UPDATE chio_threshold_approval_collector_votes SET token_id = 'different-token'",
        "UPDATE chio_threshold_approval_collector_votes SET canonical_token_digest = 'different-digest'",
        "UPDATE chio_threshold_approval_collector_votes SET approver_fingerprint = 'different-approver'",
        "UPDATE chio_threshold_approval_collector_votes SET token_json = x'7b7d'",
        "UPDATE chio_threshold_approval_collector_votes SET received_at = 100",
        "UPDATE chio_threshold_approval_collector_votes SET received_at = -1",
        "UPDATE chio_threshold_approval_collector_votes SET received_at = 111",
    ] {
        let fixture = Fixture::new()?;
        assert_eq!(fixture.connection()?.execute(mutation, [])?, 1);
        fixture.assert_rejected_without_writes()?;
    }
    Ok(())
}

#[test]
fn recovered_creation_retry_rechecks_all_persisted_material() -> TestResult {
    let fixture = Fixture::new()?;
    let initial = chio_core::canonical_json_bytes(&fixture.initial)?;
    fixture.connection()?.execute(
        "UPDATE chio_threshold_approval_collectors SET record_json = ?1",
        [&initial],
    )?;
    let (store, _) = fixture.reopen()?;
    assert!(store.create(&fixture.initial).is_err());
    Ok(())
}

#[test]
fn recovered_delivery_preserves_signed_tokens_and_terminal_state() -> TestResult {
    let fixture = Fixture::new()?;
    let (_, collector) = fixture.reopen()?;
    let delivered = collector.deliver("proposal-1", 120)?;
    assert_eq!(delivered.proposal, fixture.initial.proposal);
    assert_eq!(delivered.tokens, vec![fixture.vote.clone()]);
    drop(collector);
    let (_, collector) = fixture.reopen()?;
    let restored = collector
        .get_proposal("proposal-1")?
        .ok_or("missing proposal")?;
    assert_eq!(restored.state, ThresholdApprovalCollectorState::Delivered);
    assert!(collector.deliver("proposal-1", 121).is_err());
    Ok(())
}

#[test]
fn concurrent_identical_creations_are_idempotent() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, _) = fixture.reopen()?;
    let mut initial = fixture.initial.clone();
    let mut body = initial.proposal.body.clone();
    body.proposal_id = "concurrent-proposal".into();
    initial.proposal = ThresholdApprovalProposal::sign(body, &fixture.authority)?;
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let store = store.clone();
            let initial = initial.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.create(&initial)
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().map_err(|_| "creation worker panicked")??;
    }
    assert_eq!(store.get("concurrent-proposal")?, Some(initial));
    Ok(())
}

#[test]
fn concurrent_delivery_transitions_have_exactly_one_winner() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, _) = fixture.reopen()?;
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.transition(
                    "proposal-1",
                    1,
                    ThresholdApprovalCollectorState::Delivered,
                    120,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut winners = 0;
    for worker in workers {
        match worker.join().map_err(|_| "delivery worker panicked")? {
            Ok(_) => winners += 1,
            Err(ThresholdApprovalCollectorStoreError::Conflict(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!(winners, 1);
    let persisted = store.get("proposal-1")?.ok_or("missing proposal")?;
    assert_eq!(persisted.state, ThresholdApprovalCollectorState::Delivered);
    assert_eq!(persisted.version, 2);
    Ok(())
}

#[test]
fn integer_overflow_rolls_back_vote_and_parent_changes() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, _) = fixture.reopen()?;
    let mut record = store.get("proposal-1")?.ok_or("missing proposal")?;
    record.version = u64::try_from(i64::MAX)?;
    fixture.connection()?.execute(
        "UPDATE chio_threshold_approval_collectors SET version = ?1, record_json = ?2",
        rusqlite::params![i64::MAX, chio_core::canonical_json_bytes(&record)?],
    )?;
    assert!(store
        .append_token(
            "proposal-1",
            record.version,
            &fixture.vote,
            Some("vote-1"),
            ThresholdApprovalCollectorState::Ready,
            120,
        )
        .is_err());
    assert!(store
        .transition(
            "proposal-1",
            record.version,
            ThresholdApprovalCollectorState::Delivered,
            120,
        )
        .is_err());
    assert_eq!(store.get("proposal-1")?, Some(record));
    let received_at: i64 = fixture.connection()?.query_row(
        "SELECT received_at FROM chio_threshold_approval_collector_votes",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(received_at, 110);
    Ok(())
}

#[test]
fn creation_retry_compares_canonical_artifacts_not_optional_defaults() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, _) = fixture.reopen()?;
    let mut initial = fixture.initial.clone();
    let mut body = initial.proposal.body.clone();
    body.proposal_id = "canonical-proposal".into();
    initial.proposal = ThresholdApprovalProposal::sign(body, &fixture.authority)?;
    initial.proposal.algorithm = Some(SigningAlgorithm::Ed25519);
    store.create(&initial)?;
    // The optional default is omitted from canonical JSON and restores as None.
    store.create(&initial)?;
    initial.proposal.algorithm = None;
    store.create(&initial)?;
    assert_eq!(store.get("canonical-proposal")?, Some(initial));
    Ok(())
}
