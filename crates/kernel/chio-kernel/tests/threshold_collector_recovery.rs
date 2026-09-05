//! Recovery contracts for the collector used by the HTTP approval surface.

use std::sync::Arc;

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::crypto::{sha256_hex, Keypair, SigningAlgorithm};
use chio_kernel::threshold_approval::{
    InMemoryThresholdApprovalCollectorStore, ThresholdApprovalCollector,
    ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorState,
    ThresholdApprovalCollectorStore,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    authority: Keypair,
    approvers: [Keypair; 2],
    record: ThresholdApprovalCollectorProposal,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let authority = Keypair::generate();
        let approvers = [Keypair::generate(), Keypair::generate()];
        let requirement = ThresholdApprovalRequirement::new(
            sha256_hex(b"policy"),
            2,
            approvers
                .iter()
                .enumerate()
                .map(|(index, approver)| ThresholdApproverIdentity {
                    identifier: format!("approver-{index}"),
                    public_key: approver.public_key(),
                })
                .collect(),
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
                threshold: requirement.threshold,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: authority.public_key(),
            },
            &authority,
        )?;
        let mut fixture = Self {
            authority,
            approvers,
            record: ThresholdApprovalCollectorProposal {
                proposal,
                requirement,
                submitter: Some(Keypair::generate().public_key()),
                require_submitter_separation: true,
                state: ThresholdApprovalCollectorState::Ready,
                tokens: Vec::new(),
                version: 2,
                updated_at: 110,
            },
        };
        fixture.record.tokens = vec![fixture.token(0, "alice")?, fixture.token(1, "bob")?];
        Ok(fixture)
    }

    fn token(&self, index: usize, id: &str) -> TestResult<GovernedApprovalToken> {
        Ok(GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.into(),
                approver: self.approvers[index].public_key(),
                subject: self.record.proposal.body.subject.clone(),
                governed_intent_hash: self.record.proposal.body.governed_intent_hash.clone(),
                request_id: self.record.proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(self.record.proposal.artifact_digest()?),
                issued_at: 101,
                expires_at: 199,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approvers[index],
        )?)
    }

    fn restore(
        &self,
    ) -> TestResult<(
        Arc<InMemoryThresholdApprovalCollectorStore>,
        ThresholdApprovalCollector,
    )> {
        let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
        store.create(&self.record)?;
        let collector = ThresholdApprovalCollector::new(
            store.clone(),
            sha256_hex(b"policy"),
            vec![self.authority.public_key()],
        );
        Ok((store, collector))
    }

    fn assert_recovery_rejected(&self) -> TestResult {
        let (store, collector) = self.restore()?;
        assert!(collector.get_proposal("proposal-1").is_err());
        assert!(collector.deliver("proposal-1", 120).is_err());
        assert!(collector
            .submit_token("proposal-1", self.token(0, "fresh")?, 120)
            .is_err());
        assert!(collector.cancel("proposal-1", 120).is_err());
        assert_eq!(store.get("proposal-1")?, Some(self.record.clone()));
        Ok(())
    }
}

#[test]
fn recovery_rejects_a_tampered_proposal_without_changing_state() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.proposal.body.request_id = "different-request".into();
    fixture.assert_recovery_rejected()
}

#[test]
fn recovery_rejects_a_tampered_vote_without_changing_state() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.tokens[0].expires_at -= 1;
    fixture.assert_recovery_rejected()
}

#[test]
fn recovery_rejects_distinct_tokens_from_the_same_approver() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.tokens[1] = fixture.token(0, "duplicate-approver")?;
    fixture.assert_recovery_rejected()
}

#[test]
fn recovery_rejects_duplicate_token_ids_from_distinct_approvers() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.tokens[1] = fixture.token(1, "alice")?;
    fixture.assert_recovery_rejected()
}

#[test]
fn recovery_rejects_rebound_and_noncanonical_requirements() -> TestResult {
    for mutation in 0..3 {
        let mut fixture = Fixture::new()?;
        match mutation {
            0 => fixture.record.requirement.threshold = 1,
            1 => fixture.record.requirement.eligible_approvers.reverse(),
            _ => fixture.record.requirement.timeout_seconds = 50,
        }
        fixture.assert_recovery_rejected()?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_missing_submitter_and_self_approval() -> TestResult {
    for submitter in [None, Some(0)] {
        let mut fixture = Fixture::new()?;
        fixture.record.submitter = submitter.map(|index| fixture.approvers[index].public_key());
        fixture.assert_recovery_rejected()?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_algorithm_metadata_substitution() -> TestResult {
    for proposal in [false, true] {
        let mut fixture = Fixture::new()?;
        if proposal {
            fixture.record.proposal.algorithm = Some(SigningAlgorithm::P256);
        } else {
            fixture.record.tokens[0].algorithm = Some(SigningAlgorithm::P256);
        }
        fixture.assert_recovery_rejected()?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_state_that_precedes_its_votes() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.updated_at = 100;
    fixture.assert_recovery_rejected()
}

#[test]
fn recovery_rechecks_current_authority_and_policy() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, _) = fixture.restore()?;
    for (policy, authorities) in [
        (sha256_hex(b"policy"), Vec::new()),
        (
            sha256_hex(b"new-policy"),
            vec![fixture.authority.public_key()],
        ),
    ] {
        let collector = ThresholdApprovalCollector::new(store.clone(), policy, authorities);
        assert!(collector.get_proposal("proposal-1").is_err());
        assert!(collector.deliver("proposal-1", 120).is_err());
        assert!(collector.cancel("proposal-1", 120).is_err());
        assert_eq!(store.get("proposal-1")?, Some(fixture.record.clone()));
    }
    Ok(())
}

#[test]
fn recovery_preserves_original_tokens_and_durable_delivery() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, collector) = fixture.restore()?;
    assert_eq!(
        collector.get_proposal("proposal-1")?,
        Some(fixture.record.clone())
    );
    let delivered = collector.deliver("proposal-1", 120)?;
    assert_eq!(delivered.proposal, fixture.record.proposal);
    assert_eq!(delivered.tokens, fixture.record.tokens);
    let persisted = store.get("proposal-1")?.ok_or("missing proposal")?;
    assert_eq!(persisted.state, ThresholdApprovalCollectorState::Delivered);
    assert_eq!(persisted.version, 3);
    assert_eq!(persisted.updated_at, 120);
    assert!(collector.deliver("proposal-1", 121).is_err());
    Ok(())
}

#[test]
fn collector_rejects_clock_regression_without_changing_state() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, collector) = fixture.restore()?;
    assert!(collector.deliver("proposal-1", 109).is_err());
    assert!(collector.cancel("proposal-1", 109).is_err());
    assert_eq!(store.get("proposal-1")?, Some(fixture.record.clone()));
    Ok(())
}

#[test]
fn in_memory_version_overflow_does_not_partially_mutate_state() -> TestResult {
    for append in [false, true] {
        let mut fixture = Fixture::new()?;
        fixture.record.version = u64::MAX;
        let (store, _) = fixture.restore()?;
        let result = if append {
            store.append_token(
                "proposal-1",
                u64::MAX,
                &fixture.token(0, "fresh")?,
                Some("alice"),
                ThresholdApprovalCollectorState::Ready,
                120,
            )
        } else {
            store.transition(
                "proposal-1",
                u64::MAX,
                ThresholdApprovalCollectorState::Delivered,
                120,
            )
        };
        assert!(result.is_err());
        assert_eq!(store.get("proposal-1")?, Some(fixture.record.clone()));
    }
    Ok(())
}

#[test]
fn creation_rejects_missing_separation_identity_and_excessive_timeout() -> TestResult {
    for missing_submitter in [false, true] {
        let fixture = Fixture::new()?;
        let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
        let collector = ThresholdApprovalCollector::new(
            store.clone(),
            sha256_hex(b"policy"),
            vec![fixture.authority.public_key()],
        );
        let mut requirement = fixture.record.requirement.clone();
        let submitter = if missing_submitter {
            None
        } else {
            requirement.timeout_seconds = 99;
            fixture.record.submitter.clone()
        };
        assert!(collector
            .create_proposal(fixture.record.proposal, requirement, submitter, true, 100,)
            .is_err());
        assert!(store.get("proposal-1")?.is_none());
    }
    Ok(())
}

#[test]
fn recovery_rejects_quorum_and_version_metadata_inconsistent_with_votes() -> TestResult {
    for mutation in 0..4 {
        let mut fixture = Fixture::new()?;
        match mutation {
            0 => {
                fixture.record.tokens.pop();
            }
            1 => fixture.record.state = ThresholdApprovalCollectorState::Collecting,
            2 => fixture.record.version = 0,
            _ => fixture.record.updated_at = 199,
        }
        fixture.assert_recovery_rejected()?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_signed_votes_bound_to_different_operations() -> TestResult {
    for mutation in 0..5 {
        let mut fixture = Fixture::new()?;
        let mut body = fixture.record.tokens[0].body();
        match mutation {
            0 => body.request_id = "different-request".into(),
            1 => body.subject = Keypair::generate().public_key(),
            2 => body.threshold_proposal_hash = Some(sha256_hex(b"different-proposal")),
            3 => body.governed_intent_hash = sha256_hex(b"different-intent"),
            _ => body.expires_at = 201,
        }
        fixture.record.tokens[0] = GovernedApprovalToken::sign(body, &fixture.approvers[0])?;
        fixture.assert_recovery_rejected()?;
    }
    Ok(())
}

#[test]
fn expired_history_is_readable_but_cannot_be_delivered() -> TestResult {
    let fixture = Fixture::new()?;
    let (_, collector) = fixture.restore()?;
    assert!(collector.deliver("proposal-1", 200).is_err());
    assert_eq!(collector.get_proposal("proposal-1")?, Some(fixture.record));
    let cancelled = collector.cancel("proposal-1", 201)?;
    assert_eq!(cancelled.state, ThresholdApprovalCollectorState::Cancelled);
    assert_eq!(collector.get_proposal("proposal-1")?, Some(cancelled));
    Ok(())
}
