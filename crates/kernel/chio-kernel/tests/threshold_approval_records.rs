//! Public API contracts for validated durable approval records, not store wiring.

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequest, ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::approval::{
    ApprovalStoreError, ThresholdApprovalCollectorStatus, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalCreationParameters, ThresholdApprovalProposalRecord,
    ThresholdApprovalProposalRegistration, ThresholdApprovalVoteRecord,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    authority: Keypair,
    approvers: [Keypair; 3],
    parameters: ThresholdApprovalProposalCreationParameters,
    registration: ThresholdApprovalProposalRegistration,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let authority = Keypair::generate();
        let approvers = [
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        ];
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
        let parameters = ThresholdApprovalProposalCreationParameters {
            matched_request: ThresholdApprovalRequest::new("request-1", "server", "tool")?,
            requirement: requirement.clone(),
            subject: Keypair::generate().public_key(),
            governed_intent_hash: sha256_hex(b"intent"),
            authorization_capability_hash: sha256_hex(b"capability"),
            authorizing_capability_expires_at: 190,
            governed_operation_expires_at: 180,
            submitter: Some(Keypair::generate().public_key()),
            separation_of_duties: true,
        };
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
                proposal_id: "proposal-1".into(),
                request_id: parameters.matched_request.request_id().into(),
                governed_intent_hash: parameters.governed_intent_hash.clone(),
                subject: parameters.subject.clone(),
                authorizing_capability_digest: parameters.authorization_capability_hash.clone(),
                policy_hash: requirement.policy_hash.clone(),
                threshold: requirement.threshold,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 180,
                policy_authority: authority.public_key(),
            },
            &authority,
        )?;
        let context = ThresholdApprovalProposalCreationContext::new(parameters.clone())?;
        let registration = ThresholdApprovalProposalRegistration::new(
            proposal,
            &context,
            &[authority.public_key()],
            100,
        )?;
        Ok(Self {
            authority,
            approvers,
            parameters,
            registration,
        })
    }

    fn token(&self, index: usize, id: &str) -> TestResult<GovernedApprovalToken> {
        Ok(GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.into(),
                approver: self.approvers[index].public_key(),
                subject: self.parameters.subject.clone(),
                governed_intent_hash: self.parameters.governed_intent_hash.clone(),
                request_id: self.parameters.matched_request.request_id().into(),
                threshold_proposal_hash: Some(self.registration.proposal().proposal_hash()?),
                issued_at: 110,
                expires_at: 180,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approvers[index],
        )?)
    }

    fn votes(&self) -> TestResult<Vec<ThresholdApprovalVoteRecord>> {
        [0, 1]
            .into_iter()
            .map(|index| {
                Ok(ThresholdApprovalVoteRecord::validate_new(
                    &self.registration,
                    self.token(index, &format!("vote-{index}"))?,
                    110 + index as u64,
                    false,
                )?)
            })
            .collect()
    }
}

#[test]
fn validated_records_preserve_canonical_artifacts_and_reservation_identity() -> TestResult {
    let fixture = Fixture::new()?;
    let record = ThresholdApprovalProposalRecord::from_persisted_parts(
        fixture.registration.clone(),
        ThresholdApprovalCollectorStatus::Delivered,
        fixture.votes()?,
        Some(111),
        Some(112),
    )?;
    let reservation = record.reservation_input()?;
    let mut reversed = record.votes().to_vec();
    reversed.reverse();
    let restored = ThresholdApprovalProposalRecord::from_persisted_parts(
        fixture.registration,
        ThresholdApprovalCollectorStatus::Delivered,
        reversed,
        Some(111),
        Some(112),
    )?;
    assert_eq!(restored.reservation_input()?, reservation);
    assert_eq!(
        record.proposal().proposal_hash()?,
        restored.proposal().proposal_hash()?
    );
    Ok(())
}

#[test]
fn proposal_registration_rejects_changed_route_capability_and_deadline() -> TestResult {
    let fixture = Fixture::new()?;
    for field in ["route", "capability", "deadline", "subject", "submitter"] {
        let mut parameters = fixture.parameters.clone();
        match field {
            "route" => {
                parameters.matched_request =
                    ThresholdApprovalRequest::new("request-1", "different", "tool")?
            }
            "capability" => parameters.authorization_capability_hash = sha256_hex(b"other"),
            "deadline" => parameters.governed_operation_expires_at = 179,
            "subject" => parameters.subject = Keypair::generate().public_key(),
            "submitter" => parameters.submitter = Some(Keypair::generate().public_key()),
            _ => unreachable!(),
        }
        let context = ThresholdApprovalProposalCreationContext::new(parameters)?;
        assert!(
            matches!(
                fixture
                    .registration
                    .validate_current_context(&context, &[fixture.authority.public_key()],),
                Err(ApprovalStoreError::Conflict(_))
            ),
            "{field}"
        );
    }
    assert!(fixture
        .registration
        .validate_current_authority(
            &fixture.parameters.requirement.policy_hash,
            &[Keypair::generate().public_key()],
        )
        .is_err());
    Ok(())
}

#[test]
fn signed_vote_tampering_and_expired_reception_fail_closed() -> TestResult {
    let fixture = Fixture::new()?;
    let token = fixture.token(0, "vote")?;
    for field in ["request", "proposal", "signature"] {
        let mut changed = token.clone();
        match field {
            "request" => changed.request_id = "different".into(),
            "proposal" => changed.threshold_proposal_hash = Some(sha256_hex(b"different")),
            "signature" => changed.id = "tampered-without-resigning".into(),
            _ => unreachable!(),
        }
        assert!(
            ThresholdApprovalVoteRecord::validate_new(&fixture.registration, changed, 110, false,)
                .is_err(),
            "{field}"
        );
    }
    for received_at in [99, 109, 180, 181] {
        assert!(
            ThresholdApprovalVoteRecord::validate_new(
                &fixture.registration,
                token.clone(),
                received_at,
                false,
            )
            .is_err(),
            "{received_at}"
        );
    }
    Ok(())
}

#[test]
fn persisted_vote_metadata_cannot_substitute_a_digest_or_signer() -> TestResult {
    let fixture = Fixture::new()?;
    let vote = ThresholdApprovalVoteRecord::validate_new(
        &fixture.registration,
        fixture.token(0, "vote")?,
        110,
        false,
    )?;
    for (digest, signer) in [
        (
            sha256_hex(b"wrong"),
            vote.approver_fingerprint().to_string(),
        ),
        (
            vote.token_digest().to_string(),
            fixture.approvers[1].public_key().to_hex(),
        ),
    ] {
        assert!(matches!(
            ThresholdApprovalVoteRecord::from_persisted_parts(
                &fixture.registration,
                vote.token().clone(),
                digest,
                signer,
                110,
            ),
            Err(ApprovalStoreError::Serialization(_))
        ));
    }
    Ok(())
}

#[test]
fn duplicate_approvers_and_false_terminal_states_are_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    let first = ThresholdApprovalVoteRecord::validate_new(
        &fixture.registration,
        fixture.token(0, "vote-0")?,
        110,
        false,
    )?;
    let same_approver = ThresholdApprovalVoteRecord::validate_new(
        &fixture.registration,
        fixture.token(0, "vote-1")?,
        111,
        false,
    )?;
    for (status, votes, satisfied, delivered) in [
        (
            ThresholdApprovalCollectorStatus::Satisfied,
            vec![first.clone(), same_approver],
            Some(111),
            None,
        ),
        (
            ThresholdApprovalCollectorStatus::Satisfied,
            vec![first.clone()],
            Some(111),
            None,
        ),
        (
            ThresholdApprovalCollectorStatus::Collecting,
            fixture.votes()?,
            None,
            None,
        ),
        (
            ThresholdApprovalCollectorStatus::Delivered,
            fixture.votes()?,
            Some(111),
            None,
        ),
        (
            ThresholdApprovalCollectorStatus::Delivered,
            fixture.votes()?,
            Some(111),
            Some(110),
        ),
    ] {
        assert!(ThresholdApprovalProposalRecord::from_persisted_parts(
            fixture.registration.clone(),
            status,
            votes,
            satisfied,
            delivered,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn identical_vote_retry_is_idempotent_but_signer_reuse_is_replay() -> TestResult {
    let fixture = Fixture::new()?;
    let record = ThresholdApprovalProposalRecord::from_persisted_parts(
        fixture.registration.clone(),
        ThresholdApprovalCollectorStatus::Satisfied,
        fixture.votes()?,
        Some(111),
        None,
    )?;
    assert!(record
        .existing_vote_for(&fixture.token(0, "vote-0")?)?
        .is_some());
    assert!(matches!(
        record.existing_vote_for(&fixture.token(0, "another-id")?),
        Err(ApprovalStoreError::Replay(_))
    ));
    Ok(())
}

#[test]
fn persisted_satisfaction_requires_a_quorum_received_by_that_time() -> TestResult {
    let fixture = Fixture::new()?;
    assert!(ThresholdApprovalProposalRecord::from_persisted_parts(
        fixture.registration.clone(),
        ThresholdApprovalCollectorStatus::Satisfied,
        fixture.votes()?,
        Some(110),
        None,
    )
    .is_err());
    Ok(())
}

#[test]
fn later_surplus_votes_preserve_the_original_quorum_time() -> TestResult {
    let fixture = Fixture::new()?;
    let mut votes = fixture.votes()?;
    votes.push(ThresholdApprovalVoteRecord::validate_new(
        &fixture.registration,
        fixture.token(2, "surplus-vote")?,
        120,
        false,
    )?);
    let record = ThresholdApprovalProposalRecord::from_persisted_parts(
        fixture.registration,
        ThresholdApprovalCollectorStatus::Satisfied,
        votes,
        Some(111),
        None,
    )?;
    assert_eq!(record.satisfied_at(), Some(111));
    assert_eq!(record.votes().len(), 3);
    Ok(())
}
