//! Trusted threshold-approval policy authority.

use std::collections::BTreeSet;

use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
pub use chio_core::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    ThresholdApprovalRequirement, ThresholdApprovalRequirementError,
    ThresholdApprovalResolutionError, VerifiedApprovalSetBody, CHIO_APPROVER_SET_DIGEST_DOMAIN,
    CHIO_THRESHOLD_APPROVAL_PROPOSAL_SCHEMA, CHIO_THRESHOLD_APPROVAL_PROPOSAL_SIGNATURE_DOMAIN,
    CHIO_VERIFIED_APPROVAL_SET_DOMAIN, CHIO_VERIFIED_APPROVAL_SET_SCHEMA,
    DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS, MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
    MAX_THRESHOLD_APPROVAL_TOKENS,
};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{sha256_hex, PublicKey, SigningAlgorithm};

use crate::canonical_json_bytes;

/// Kernel-installed deterministic resolver for the currently loaded policy.
pub trait ThresholdApprovalRequirementResolver:
    chio_core::capability::threshold_approval::ThresholdApprovalRequirementResolver + Send + Sync
{
}

impl<T> ThresholdApprovalRequirementResolver for T where
    T: chio_core::capability::threshold_approval::ThresholdApprovalRequirementResolver
        + Send
        + Sync
{
}

/// Pure threshold verification inputs assembled after ordinary capability admission.
pub struct ThresholdApprovalVerificationInput<'a> {
    pub request_id: &'a str,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub governed_intent_hash: &'a str,
    pub subject: &'a PublicKey,
    pub authorization_capability_hash: &'a str,
    pub authorizing_capability_expires_at: u64,
    pub governed_operation_expires_at: u64,
    pub policy_hash: &'a str,
    pub proposal: &'a ThresholdApprovalProposal,
    pub approval_tokens: &'a [GovernedApprovalToken],
    pub trusted_policy_authorities: &'a [PublicKey],
    pub allowed_token_algorithms: &'a [SigningAlgorithm],
    pub now: u64,
}

/// Fail-closed threshold verification error without replay-store mutation.
#[derive(Debug, thiserror::Error)]
pub enum ThresholdApprovalVerificationError {
    #[error("threshold approval requirement resolution failed: {0}")]
    Requirement(String),
    #[error("threshold approval verification denied: {0}")]
    Denied(String),
}

/// Canonical digest of the complete already-verified authorizing capability.
pub fn authorization_capability_hash(
    capability: &CapabilityToken,
) -> Result<String, ThresholdApprovalVerificationError> {
    let canonical = canonical_json_bytes(capability).map_err(|error| {
        ThresholdApprovalVerificationError::Denied(format!(
            "authorizing capability canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&canonical))
}

/// Verify a complete threshold token set without reserving or consuming replay state.
pub fn verify_threshold_approval_set(
    input: &ThresholdApprovalVerificationInput<'_>,
    resolver: &dyn ThresholdApprovalRequirementResolver,
) -> Result<VerifiedApprovalSetBody, ThresholdApprovalVerificationError> {
    let token_count = input.approval_tokens.len();
    if token_count > MAX_THRESHOLD_APPROVAL_TOKENS {
        return Err(denied("approval token set exceeds the protocol ceiling"));
    }

    let matched_request =
        ThresholdApprovalRequest::new(input.request_id, input.server_id, input.tool_name)
            .map_err(|error| denied(&format!("matched request is invalid: {error}")))?;
    let requirement = resolver
        .resolve_threshold_approval_requirement(&matched_request, input.policy_hash)
        .map_err(|error| ThresholdApprovalVerificationError::Requirement(error.to_string()))?;

    if token_count > requirement.eligible().len() {
        return Err(denied(
            "approval token set exceeds the policy-owned eligible signer count",
        ));
    }
    let required = usize::try_from(requirement.required())
        .map_err(|_| denied("threshold does not fit this platform"))?;
    if token_count < required {
        return Err(denied("approval token set does not satisfy threshold"));
    }
    if requirement.policy_hash() != input.policy_hash {
        return Err(denied(
            "resolved threshold requirement carries a stale policy hash",
        ));
    }

    let proposal = input.proposal;
    let proposal_body = proposal.body();
    if !input
        .trusted_policy_authorities
        .contains(proposal.policy_authority())
    {
        return Err(denied(
            "threshold proposal signer is not a trusted policy authority",
        ));
    }
    if !proposal
        .verify_signature()
        .map_err(|error| denied(&format!("threshold proposal signature failed: {error}")))?
    {
        return Err(denied("threshold proposal signature did not verify"));
    }

    if proposal_body.request_id() != input.request_id {
        return Err(denied("threshold proposal request binding does not match"));
    }
    if proposal_body.governed_intent_hash() != input.governed_intent_hash {
        return Err(denied("threshold proposal intent binding does not match"));
    }
    if proposal_body.subject() != input.subject {
        return Err(denied("threshold proposal subject binding does not match"));
    }
    if proposal_body.authorization_capability_hash() != input.authorization_capability_hash {
        return Err(denied(
            "threshold proposal authorizing capability binding does not match",
        ));
    }
    if proposal_body.policy_hash() != input.policy_hash
        || proposal_body.policy_hash() != requirement.policy_hash()
    {
        return Err(denied("threshold proposal policy binding is stale"));
    }
    if proposal_body.required() != requirement.required() {
        return Err(denied(
            "threshold proposal weakens or changes the required count",
        ));
    }
    if proposal_body.eligible_set_digest() != requirement.eligible_set_digest() {
        return Err(denied(
            "threshold proposal eligible-set binding does not match",
        ));
    }

    let timeout_deadline = proposal_body
        .proposal_created_at()
        .checked_add(requirement.proposal_timeout_seconds())
        .ok_or_else(|| denied("threshold proposal deadline arithmetic overflowed"))?;
    let expected_deadline = timeout_deadline
        .min(input.authorizing_capability_expires_at)
        .min(input.governed_operation_expires_at);
    if proposal_body.proposal_deadline() != expected_deadline {
        return Err(denied(
            "threshold proposal deadline does not match authority bounds",
        ));
    }
    if input.now < proposal_body.proposal_created_at() {
        return Err(denied("threshold proposal is not yet valid"));
    }
    if input.now >= proposal_body.proposal_deadline() {
        return Err(denied("threshold proposal has expired"));
    }

    let proposal_hash = proposal
        .proposal_hash()
        .map_err(|error| denied(&format!("threshold proposal hash failed: {error}")))?;
    let eligible_keys = requirement
        .eligible()
        .values()
        .map(PublicKey::to_hex)
        .collect::<BTreeSet<_>>();
    let mut token_ids = BTreeSet::new();
    let mut token_digests = BTreeSet::new();
    let mut signer_fingerprints = BTreeSet::new();

    for token in input.approval_tokens {
        if token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str()) {
            return Err(denied("approval token proposal binding does not match"));
        }
        if token.request_id != input.request_id {
            return Err(denied("approval token request binding does not match"));
        }
        if token.governed_intent_hash != input.governed_intent_hash {
            return Err(denied("approval token intent binding does not match"));
        }
        if &token.subject != input.subject {
            return Err(denied("approval token subject binding does not match"));
        }
        if token.decision != GovernedApprovalDecision::Approved {
            return Err(denied("approval token decision is not approved"));
        }
        if token.id.is_empty() || token.id.trim() != token.id {
            return Err(denied("approval token ID is empty or not normalized"));
        }
        if token.issued_at < proposal_body.proposal_created_at()
            || token.issued_at >= proposal_body.proposal_deadline()
        {
            return Err(denied(
                "approval token issuance is outside the proposal window",
            ));
        }
        if input.now < token.issued_at {
            return Err(denied("approval token is not yet valid"));
        }
        if token.expires_at <= token.issued_at
            || token.expires_at > proposal_body.proposal_deadline()
            || input.now >= token.expires_at
        {
            return Err(denied(
                "approval token expiry is outside the proposal window",
            ));
        }

        let algorithm = token.algorithm.unwrap_or_default();
        if !input.allowed_token_algorithms.contains(&algorithm)
            || token.approver.algorithm() != algorithm
            || token.signature.algorithm() != algorithm
        {
            return Err(denied("approval token signing algorithm is not allowed"));
        }
        if !eligible_keys.contains(&token.approver.to_hex()) {
            return Err(denied("approval token signer is not policy-eligible"));
        }
        if !token
            .verify_signature()
            .map_err(|error| denied(&format!("approval token signature failed: {error}")))?
        {
            return Err(denied("approval token signature did not verify"));
        }

        let digest = token
            .token_digest()
            .map_err(|error| denied(&format!("approval token digest failed: {error}")))?;
        if !token_ids.insert(token.id.clone()) {
            return Err(denied("approval token ID is duplicated"));
        }
        if !token_digests.insert(digest) {
            return Err(denied("approval token digest is duplicated"));
        }
        if !signer_fingerprints.insert(token.approver.to_hex()) {
            return Err(denied("approval token signer is duplicated"));
        }
    }

    VerifiedApprovalSetBody::new(token_digests.into_iter().collect(), proposal).map_err(|error| {
        denied(&format!(
            "verified approval set construction failed: {error}"
        ))
    })
}

fn denied(reason: &str) -> ThresholdApprovalVerificationError {
    ThresholdApprovalVerificationError::Denied(reason.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chio_core::capability::governance::GovernedApprovalTokenBody;
    use chio_core::crypto::Keypair;

    use super::*;

    struct Fixture {
        authority: Keypair,
        subject: Keypair,
        approvers: Vec<Keypair>,
        requirement: ThresholdApprovalRequirement,
        proposal: ThresholdApprovalProposal,
        intent_hash: String,
        capability_hash: String,
    }

    impl Fixture {
        fn new() -> Self {
            let authority = Keypair::generate();
            let subject = Keypair::generate();
            let approvers = vec![Keypair::generate(), Keypair::generate()];
            let policy_hash = "33".repeat(32);
            let intent_hash = "11".repeat(32);
            let capability_hash = "22".repeat(32);
            let requirement = ThresholdApprovalRequirement::new(
                2,
                BTreeMap::from([
                    ("alice".to_string(), approvers[0].public_key()),
                    ("bob".to_string(), approvers[1].public_key()),
                ]),
                900,
                policy_hash.clone(),
                1,
            )
            .expect("requirement");
            let proposal_body = ThresholdApprovalProposalBody::new(
                "proposal-1",
                "request-1",
                intent_hash.clone(),
                subject.public_key(),
                capability_hash.clone(),
                policy_hash,
                requirement.required(),
                requirement.eligible_set_digest(),
                1_000,
                requirement.proposal_timeout_seconds(),
                1_900,
                1_900,
            )
            .expect("proposal body");
            let proposal = ThresholdApprovalProposal::sign(proposal_body, &authority)
                .expect("signed proposal");
            Self {
                authority,
                subject,
                approvers,
                requirement,
                proposal,
                intent_hash,
                capability_hash,
            }
        }

        fn token(&self, index: usize, id: &str) -> GovernedApprovalToken {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: id.to_string(),
                    approver: self.approvers[index].public_key(),
                    subject: self.subject.public_key(),
                    governed_intent_hash: self.intent_hash.clone(),
                    threshold_proposal_hash: Some(
                        self.proposal.proposal_hash().expect("proposal hash"),
                    ),
                    request_id: "request-1".to_string(),
                    issued_at: 1_100,
                    expires_at: 1_800,
                    decision: GovernedApprovalDecision::Approved,
                },
                &self.approvers[index],
            )
            .expect("signed approval")
        }

        fn verify(
            &self,
            tokens: &[GovernedApprovalToken],
        ) -> Result<VerifiedApprovalSetBody, ThresholdApprovalVerificationError> {
            let trusted_authorities = [self.authority.public_key()];
            verify_threshold_approval_set(
                &ThresholdApprovalVerificationInput {
                    request_id: "request-1",
                    server_id: "payments",
                    tool_name: "transfer",
                    governed_intent_hash: &self.intent_hash,
                    subject: &self.subject.public_key(),
                    authorization_capability_hash: &self.capability_hash,
                    authorizing_capability_expires_at: 1_900,
                    governed_operation_expires_at: 1_900,
                    policy_hash: self.requirement.policy_hash(),
                    proposal: &self.proposal,
                    approval_tokens: tokens,
                    trusted_policy_authorities: &trusted_authorities,
                    allowed_token_algorithms: &[SigningAlgorithm::Ed25519],
                    now: 1_200,
                },
                &|_: &ThresholdApprovalRequest, _: &str| Ok(self.requirement.clone()),
            )
        }
    }

    #[test]
    fn pure_verifier_is_order_independent() {
        let fixture = Fixture::new();
        let first = fixture.token(0, "approval-a");
        let second = fixture.token(1, "approval-b");
        let left = fixture
            .verify(&[first.clone(), second.clone()])
            .expect("left set");
        let right = fixture.verify(&[second, first]).expect("right set");
        assert_eq!(left, right);
        assert_eq!(
            left.approval_set_hash().expect("left hash"),
            right.approval_set_hash().expect("right hash")
        );
    }

    #[test]
    fn pure_verifier_rejects_n_minus_one_and_duplicate_signers() {
        let fixture = Fixture::new();
        let first = fixture.token(0, "approval-a");
        assert!(fixture.verify(std::slice::from_ref(&first)).is_err());

        let duplicate = fixture.token(0, "approval-b");
        let error = fixture
            .verify(&[first, duplicate])
            .expect_err("duplicate signer must deny");
        assert!(error.to_string().contains("signer is duplicated"));
    }

    #[test]
    fn pure_verifier_rejects_future_issued_token() {
        let fixture = Fixture::new();
        let future = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "approval-future".to_string(),
                approver: fixture.approvers[0].public_key(),
                subject: fixture.subject.public_key(),
                governed_intent_hash: fixture.intent_hash.clone(),
                threshold_proposal_hash: Some(
                    fixture.proposal.proposal_hash().expect("proposal hash"),
                ),
                request_id: "request-1".to_string(),
                issued_at: 1_300,
                expires_at: 1_800,
                decision: GovernedApprovalDecision::Approved,
            },
            &fixture.approvers[0],
        )
        .expect("future approval");
        let second = fixture.token(1, "approval-b");
        let error = fixture
            .verify(&[future, second])
            .expect_err("future-issued approval must deny");
        assert!(error.to_string().contains("not yet valid"));
    }

    #[test]
    fn pure_verifier_surfaces_stale_policy_resolution() {
        let fixture = Fixture::new();
        let tokens = [
            fixture.token(0, "approval-a"),
            fixture.token(1, "approval-b"),
        ];
        let trusted_authorities = [fixture.authority.public_key()];
        let error = verify_threshold_approval_set(
            &ThresholdApprovalVerificationInput {
                request_id: "request-1",
                server_id: "payments",
                tool_name: "transfer",
                governed_intent_hash: &fixture.intent_hash,
                subject: &fixture.subject.public_key(),
                authorization_capability_hash: &fixture.capability_hash,
                authorizing_capability_expires_at: 1_900,
                governed_operation_expires_at: 1_900,
                policy_hash: fixture.requirement.policy_hash(),
                proposal: &fixture.proposal,
                approval_tokens: &tokens,
                trusted_policy_authorities: &trusted_authorities,
                allowed_token_algorithms: &[SigningAlgorithm::Ed25519],
                now: 1_200,
            },
            &|_: &ThresholdApprovalRequest, _: &str| {
                Err(ThresholdApprovalResolutionError::StalePolicy {
                    expected: "44".repeat(32),
                    received: "33".repeat(32),
                })
            },
        )
        .expect_err("stale policy must deny");
        assert!(error.to_string().contains("stale"));
    }
}
