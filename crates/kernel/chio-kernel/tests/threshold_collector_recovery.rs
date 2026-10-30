//! Recovery contracts for the collector used by the HTTP approval surface.

use std::sync::{Arc, RwLock};

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequest, ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::approval::{
    ApprovalStoreError, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalCreationParameters,
};
use chio_kernel::threshold_approval::{
    InMemoryThresholdApprovalCollectorStore, ThresholdApprovalCollector,
    ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorState,
    ThresholdApprovalCollectorStore, ThresholdApprovalCollectorStoreError,
};
use chio_kernel::ThresholdApprovalContextResolver;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SIGNER_NOT_TRUSTED: &str = "threshold approval proposal signer or signature is not trusted";
const TOKEN_UNVERIFIED: &str = "threshold approval token signature did not verify";
const TOKEN_NOT_UNIQUE: &str = "threshold approval token id, digest, and signer must be unique";
const TOKEN_PROPOSAL_MISMATCH: &str = "threshold approval token does not match the signed proposal";
const STATE_VOTES_MISMATCH: &str = "threshold approval state does not match its collected votes";
const VERSION_OVERFLOW: &str = "proposal version overflowed";
const AUTHORITY_UNAVAILABLE: &str = "authority unavailable";
const REQUEST_BINDINGS: &str =
    "approval state conflict: threshold proposal does not match the authenticated request bindings";
const AUTHORITY_BOUNDS: &str =
    "approval state conflict: threshold proposal deadline does not match authenticated authority bounds";
const ROUTE_OR_REQUIREMENT_CHANGED: &str =
    "threshold approval request route or policy requirement changed";

#[track_caller]
fn assert_conflict<T: std::fmt::Debug>(
    result: Result<T, ThresholdApprovalCollectorStoreError>,
    expected: &str,
) {
    match result {
        Err(ThresholdApprovalCollectorStoreError::Conflict(message)) => {
            assert_eq!(message, expected);
        }
        other => panic!("expected Conflict({expected:?}), got {other:?}"),
    }
}

#[track_caller]
fn assert_backend<T: std::fmt::Debug>(
    result: Result<T, ThresholdApprovalCollectorStoreError>,
    expected: &str,
) {
    match result {
        Err(ThresholdApprovalCollectorStoreError::Backend(message)) => {
            assert_eq!(message, expected);
        }
        other => panic!("expected Backend({expected:?}), got {other:?}"),
    }
}

struct Fixture {
    authority: Keypair,
    approvers: [Keypair; 2],
    record: ThresholdApprovalCollectorProposal,
    context: ThresholdApprovalProposalCreationContext,
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
        let route = ThresholdApprovalRequest::new("request-1", "server", "tool")?;
        let submitter = Some(Keypair::generate().public_key());
        let context = ThresholdApprovalProposalCreationContext::new(
            ThresholdApprovalProposalCreationParameters {
                matched_request: route.clone(),
                requirement: requirement.clone(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                authorization_capability_hash: proposal.body.authorizing_capability_digest.clone(),
                authorizing_capability_expires_at: 200,
                governed_operation_expires_at: 200,
                submitter: submitter.clone(),
                separation_of_duties: true,
            },
        )?;
        let mut fixture = Self {
            authority,
            approvers,
            context,
            record: ThresholdApprovalCollectorProposal {
                proposal,
                request_route: Some(route),
                requirement,
                submitter,
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
            self.resolver(),
        );
        Ok((store, collector))
    }

    fn resolver(&self) -> Arc<dyn ThresholdApprovalContextResolver> {
        let context = self.context.clone();
        Arc::new(move |_: &str, _: u64| Ok(context.clone()))
    }

    fn parameters(&self) -> ThresholdApprovalProposalCreationParameters {
        ThresholdApprovalProposalCreationParameters {
            matched_request: self.context.matched_request().clone(),
            requirement: self.context.requirement().clone(),
            subject: self.context.subject().clone(),
            governed_intent_hash: self.context.governed_intent_hash().into(),
            authorization_capability_hash: self.context.authorization_capability_hash().into(),
            authorizing_capability_expires_at: self.context.authorizing_capability_expires_at(),
            governed_operation_expires_at: self.context.governed_operation_expires_at(),
            submitter: self.context.submitter().cloned(),
            separation_of_duties: self.context.separation_of_duties(),
        }
    }

    fn assert_recovery_rejected(&self, expected: &str) -> TestResult {
        let (store, collector) = self.restore()?;
        assert_conflict(collector.get_proposal("proposal-1", 120), expected);
        assert_conflict(collector.deliver("proposal-1", 120), expected);
        assert_conflict(
            collector.submit_token("proposal-1", self.token(0, "fresh")?, 120),
            expected,
        );
        assert_conflict(collector.cancel("proposal-1", 120), expected);
        assert_eq!(store.get("proposal-1")?, Some(self.record.clone()));
        Ok(())
    }
}

#[test]
fn recovery_rejects_a_tampered_proposal_without_changing_state() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.proposal.body.request_id = "different-request".into();
    fixture.assert_recovery_rejected(SIGNER_NOT_TRUSTED)
}

#[test]
fn recovery_rejects_a_tampered_vote_without_changing_state() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.tokens[0].expires_at -= 1;
    fixture.assert_recovery_rejected(TOKEN_UNVERIFIED)
}

#[test]
fn recovery_rejects_distinct_tokens_from_the_same_approver() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.tokens[1] = fixture.token(0, "duplicate-approver")?;
    fixture.assert_recovery_rejected(TOKEN_NOT_UNIQUE)
}

#[test]
fn recovery_rejects_duplicate_token_ids_from_distinct_approvers() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.tokens[1] = fixture.token(1, "alice")?;
    fixture.assert_recovery_rejected(TOKEN_NOT_UNIQUE)
}

#[test]
fn recovery_rejects_rebound_and_noncanonical_requirements() -> TestResult {
    for mutation in 0..3 {
        let mut fixture = Fixture::new()?;
        let expected = match mutation {
            0 => {
                fixture.record.requirement.threshold = 1;
                "threshold approval proposal does not match its approver requirement"
            }
            1 => {
                fixture.record.requirement.eligible_approvers.reverse();
                "threshold approval requirement is not canonical"
            }
            _ => {
                fixture.record.requirement.timeout_seconds = 50;
                "threshold approval proposal exceeds its policy timeout"
            }
        };
        fixture.assert_recovery_rejected(expected)?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_missing_submitter_and_self_approval() -> TestResult {
    for (submitter, expected) in [
        (
            None,
            "threshold approval separation requires an authenticated submitter",
        ),
        (
            Some(0),
            "threshold approval submitter cannot approve their own proposal",
        ),
    ] {
        let mut fixture = Fixture::new()?;
        fixture.record.submitter = submitter.map(|index| fixture.approvers[index].public_key());
        fixture.assert_recovery_rejected(expected)?;
    }
    Ok(())
}

#[test]
fn recovery_rejects_state_that_precedes_its_votes() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.updated_at = 100;
    fixture.assert_recovery_rejected("threshold approval state precedes a collected token")
}

#[test]
fn recovery_rechecks_current_authority_and_policy() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, _) = fixture.restore()?;
    for (policy, authorities, expected) in [
        (sha256_hex(b"policy"), Vec::new(), SIGNER_NOT_TRUSTED),
        (
            sha256_hex(b"new-policy"),
            vec![fixture.authority.public_key()],
            "threshold approval proposal is stale for the active policy",
        ),
    ] {
        let collector =
            ThresholdApprovalCollector::new(store.clone(), policy, authorities, fixture.resolver());
        assert_conflict(collector.get_proposal("proposal-1", 120), expected);
        assert_conflict(collector.deliver("proposal-1", 120), expected);
        assert_conflict(collector.cancel("proposal-1", 120), expected);
        assert_eq!(store.get("proposal-1")?, Some(fixture.record.clone()));
    }
    Ok(())
}

#[test]
fn recovery_preserves_original_tokens_and_durable_delivery() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, collector) = fixture.restore()?;
    assert_eq!(
        collector.get_proposal("proposal-1", 120)?,
        Some(fixture.record.clone())
    );
    let delivered = collector.deliver("proposal-1", 120)?;
    assert_eq!(delivered.proposal, fixture.record.proposal);
    assert_eq!(delivered.tokens, fixture.record.tokens);
    let persisted = store.get("proposal-1")?.ok_or("missing proposal")?;
    assert_eq!(persisted.state, ThresholdApprovalCollectorState::Delivered);
    assert_eq!(persisted.version, 3);
    assert_eq!(persisted.updated_at, 120);
    assert_eq!(collector.deliver("proposal-1", 121)?, delivered);
    assert_eq!(store.get("proposal-1")?, Some(persisted));
    Ok(())
}

#[test]
fn collector_rejects_clock_regression_without_changing_state() -> TestResult {
    let fixture = Fixture::new()?;
    let (store, collector) = fixture.restore()?;
    let expected = "threshold approval update precedes its persisted state";
    assert_conflict(collector.deliver("proposal-1", 109), expected);
    assert_conflict(collector.cancel("proposal-1", 109), expected);
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
        assert_conflict(result, VERSION_OVERFLOW);
        assert_eq!(store.get("proposal-1")?, Some(fixture.record.clone()));
    }
    Ok(())
}

#[test]
fn creation_rejects_missing_separation_identity_and_excessive_timeout() -> TestResult {
    for (missing_submitter, expected) in [
        (false, AUTHORITY_BOUNDS),
        (
            true,
            "invalid approval reservation: separation of duties requires an authenticated submitter",
        ),
    ] {
        let fixture = Fixture::new()?;
        let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
        let mut parameters = fixture.parameters();
        if missing_submitter {
            parameters.submitter = None;
        } else {
            parameters.requirement.timeout_seconds = 99;
        }
        let collector = ThresholdApprovalCollector::new(
            store.clone(),
            sha256_hex(b"policy"),
            vec![fixture.authority.public_key()],
            Arc::new(move |_: &str, _: u64| {
                ThresholdApprovalProposalCreationContext::new(parameters.clone())
            }),
        );
        assert_conflict(
            collector.create_proposal(fixture.record.proposal, 100),
            expected,
        );
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
        fixture.assert_recovery_rejected(STATE_VOTES_MISMATCH)?;
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
        fixture.assert_recovery_rejected(TOKEN_PROPOSAL_MISMATCH)?;
    }
    Ok(())
}

#[test]
fn expired_history_is_readable_but_cannot_be_delivered() -> TestResult {
    let fixture = Fixture::new()?;
    let (_, collector) = fixture.restore()?;
    assert_conflict(
        collector.deliver("proposal-1", 200),
        "capability expired at 200",
    );
    assert_eq!(
        collector.get_proposal("proposal-1", 120)?,
        Some(fixture.record)
    );
    let cancelled = collector.cancel("proposal-1", 201)?;
    assert_eq!(cancelled.state, ThresholdApprovalCollectorState::Cancelled);
    assert_eq!(collector.get_proposal("proposal-1", 201)?, Some(cancelled));
    Ok(())
}

#[test]
fn collector_reloads_trusted_context_before_every_operation() -> TestResult {
    for (field, expected) in [
        (
            "request",
            "threshold approval context resolved a different request",
        ),
        ("route", ROUTE_OR_REQUIREMENT_CHANGED),
        ("intent", REQUEST_BINDINGS),
        ("capability", REQUEST_BINDINGS),
        ("capability_expiry", AUTHORITY_BOUNDS),
        ("operation_expiry", AUTHORITY_BOUNDS),
        ("subject", REQUEST_BINDINGS),
        (
            "submitter",
            "approval state conflict: threshold proposal authenticated submitter changed",
        ),
        (
            "separation",
            "approval state conflict: threshold proposal separation-of-duties policy changed",
        ),
        ("policy", ROUTE_OR_REQUIREMENT_CHANGED),
    ] {
        let fixture = Fixture::new()?;
        let parameters = Arc::new(RwLock::new(fixture.parameters()));
        let resolver_parameters = parameters.clone();
        let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
        store.create(&fixture.record)?;
        let collector = ThresholdApprovalCollector::new(
            store.clone(),
            sha256_hex(b"policy"),
            vec![fixture.authority.public_key()],
            Arc::new(move |_: &str, _: u64| {
                let parameters = resolver_parameters
                    .read()
                    .map_err(|_| ApprovalStoreError::Backend("context lock poisoned".into()))?;
                ThresholdApprovalProposalCreationContext::new(parameters.clone())
            }),
        );
        assert!(collector.get_proposal("proposal-1", 120)?.is_some());
        {
            let mut current = parameters.write().map_err(|_| "context lock poisoned")?;
            match field {
                "request" => {
                    current.matched_request =
                        ThresholdApprovalRequest::new("different", "server", "tool")?
                }
                "route" => {
                    current.matched_request =
                        ThresholdApprovalRequest::new("request-1", "other-server", "tool")?
                }
                "intent" => current.governed_intent_hash = sha256_hex(b"changed"),
                "capability" => current.authorization_capability_hash = sha256_hex(b"changed"),
                "capability_expiry" => current.authorizing_capability_expires_at = 150,
                "operation_expiry" => current.governed_operation_expires_at = 150,
                "subject" => current.subject = Keypair::generate().public_key(),
                "submitter" => current.submitter = Some(Keypair::generate().public_key()),
                "separation" => current.separation_of_duties = false,
                "policy" => current.requirement.policy_hash = sha256_hex(b"new-policy"),
                _ => return Err("unknown context mutation".into()),
            }
        }
        assert_conflict(collector.get_proposal("proposal-1", 120), expected);
        assert_conflict(collector.deliver("proposal-1", 120), expected);
        assert_conflict(
            collector.submit_token("proposal-1", fixture.token(0, "fresh")?, 120),
            expected,
        );
        assert_conflict(collector.cancel("proposal-1", 120), expected);
        assert_conflict(
            collector.bind_existing_proposal("proposal-1", 120),
            expected,
        );
        assert_eq!(store.get("proposal-1")?, Some(fixture.record));
    }
    Ok(())
}

#[test]
fn unavailable_context_never_falls_back_to_signed_proposal_fields() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
    let collector = ThresholdApprovalCollector::new(
        store.clone(),
        sha256_hex(b"policy"),
        vec![fixture.authority.public_key()],
        Arc::new(|_: &str, _: u64| {
            Err(ApprovalStoreError::Backend("authority unavailable".into()))
        }),
    );
    assert_backend(
        collector.create_proposal(fixture.record.proposal.clone(), 100),
        AUTHORITY_UNAVAILABLE,
    );
    assert!(store.get("proposal-1")?.is_none());
    store.create(&fixture.record)?;
    assert_backend(
        collector.get_proposal("proposal-1", 120),
        AUTHORITY_UNAVAILABLE,
    );
    assert_backend(collector.deliver("proposal-1", 120), AUTHORITY_UNAVAILABLE);
    assert_eq!(store.get("proposal-1")?, Some(fixture.record));
    Ok(())
}

#[test]
fn unbound_legacy_record_cannot_gain_authority_from_a_matching_live_context() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.request_route = None;
    fixture.assert_recovery_rejected(
        "threshold approval proposal requires authenticated context migration",
    )
}

#[test]
fn acknowledged_retries_preserve_votes_delivery_and_transition_time() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
    let collector = ThresholdApprovalCollector::new(
        store.clone(),
        sha256_hex(b"policy"),
        vec![fixture.authority.public_key()],
        fixture.resolver(),
    );
    collector.create_proposal(fixture.record.proposal.clone(), 100)?;
    let first = fixture.token(0, "first")?;
    let collecting = collector.submit_token("proposal-1", first.clone(), 110)?;
    assert_eq!(
        collector.create_proposal(fixture.record.proposal.clone(), 115)?,
        collecting
    );
    assert_eq!(
        collector.submit_token("proposal-1", first.clone(), 116)?,
        collecting
    );
    collector.submit_token("proposal-1", fixture.token(1, "second")?, 117)?;
    let response = collector.deliver("proposal-1", 118)?;
    let terminal = collector
        .get_proposal("proposal-1", 119)?
        .ok_or("missing proposal")?;
    assert_eq!(
        collector.create_proposal(fixture.record.proposal, 120)?,
        terminal
    );
    assert_eq!(collector.submit_token("proposal-1", first, 121)?, terminal);
    assert_eq!(collector.deliver("proposal-1", 122)?, response);
    assert_eq!(store.get("proposal-1")?, Some(terminal));
    Ok(())
}

#[test]
fn explicit_context_migration_preserves_retained_history_and_is_idempotent() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.request_route = None;
    let (store, collector) = fixture.restore()?;
    let bound = collector.bind_existing_proposal("proposal-1", 120)?;
    assert_eq!(
        bound.request_route.as_ref(),
        Some(fixture.context.matched_request())
    );
    assert_eq!(bound.tokens, fixture.record.tokens);
    assert_eq!(bound.updated_at, fixture.record.updated_at);
    assert_eq!(bound.version, fixture.record.version + 1);
    assert_eq!(collector.bind_existing_proposal("proposal-1", 121)?, bound);
    assert_eq!(store.get("proposal-1")?, Some(bound));
    assert_eq!(
        collector.deliver("proposal-1", 122)?.tokens,
        fixture.record.tokens
    );
    Ok(())
}

#[test]
fn explicit_context_migration_denies_changed_or_unavailable_authority() -> TestResult {
    for unavailable in [false, true] {
        let mut fixture = Fixture::new()?;
        fixture.record.request_route = None;
        let store = Arc::new(InMemoryThresholdApprovalCollectorStore::new());
        store.create(&fixture.record)?;
        let mut parameters = fixture.parameters();
        parameters.authorization_capability_hash = sha256_hex(b"changed-capability");
        let collector = ThresholdApprovalCollector::new(
            store.clone(),
            sha256_hex(b"policy"),
            vec![fixture.authority.public_key()],
            Arc::new(move |_: &str, _: u64| {
                if unavailable {
                    Err(ApprovalStoreError::Backend("authority unavailable".into()))
                } else {
                    ThresholdApprovalProposalCreationContext::new(parameters.clone())
                }
            }),
        );
        let result = collector.bind_existing_proposal("proposal-1", 120);
        if unavailable {
            assert_backend(result, AUTHORITY_UNAVAILABLE);
        } else {
            assert_conflict(result, REQUEST_BINDINGS);
        }
        assert_eq!(store.get("proposal-1")?, Some(fixture.record));
    }
    Ok(())
}

#[test]
fn explicit_context_migration_version_overflow_preserves_unbound_history() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.request_route = None;
    fixture.record.version = u64::MAX;
    let (store, collector) = fixture.restore()?;
    assert_conflict(
        collector.bind_existing_proposal("proposal-1", 120),
        VERSION_OVERFLOW,
    );
    assert_eq!(store.get("proposal-1")?, Some(fixture.record));
    Ok(())
}

#[test]
fn restored_votes_must_fit_the_execution_replay_identifier_contract() -> TestResult {
    for id in ["x".repeat(513), "embedded\u{0000}nul".to_string()] {
        let mut fixture = Fixture::new()?;
        fixture.record.tokens[0] = fixture.token(0, &id)?;
        fixture.assert_recovery_rejected(TOKEN_PROPOSAL_MISMATCH)?;
    }
    Ok(())
}

#[test]
fn delivery_retry_never_shrinks_the_original_set_when_a_surplus_vote_expires() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.record.requirement.threshold = 1;
    let mut parameters = fixture.parameters();
    parameters.requirement.threshold = 1;
    fixture.context = ThresholdApprovalProposalCreationContext::new(parameters)?;
    let mut body = fixture.record.proposal.body.clone();
    body.threshold = 1;
    fixture.record.proposal = ThresholdApprovalProposal::sign(body, &fixture.authority)?;
    let mut short_vote = fixture.token(0, "short-vote")?.body();
    short_vote.expires_at = 130;
    fixture.record.tokens = vec![
        GovernedApprovalToken::sign(short_vote, &fixture.approvers[0])?,
        fixture.token(1, "long-vote")?,
    ];
    let (store, collector) = fixture.restore()?;
    let delivered = collector.deliver("proposal-1", 120)?;
    assert_eq!(delivered.tokens.len(), 2);
    assert_eq!(collector.deliver("proposal-1", 129)?, delivered);
    assert_conflict(
        collector.deliver("proposal-1", 130),
        "threshold approval quorum is no longer satisfied",
    );
    let persisted = store.get("proposal-1")?.ok_or("missing proposal")?;
    assert_eq!(persisted.updated_at, 120);
    assert_eq!(persisted.version, 3);
    assert_eq!(persisted.tokens, delivered.tokens);
    Ok(())
}
