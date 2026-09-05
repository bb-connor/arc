//! Pure execution-time verification of policy-bound threshold approval sets.
//!
//! Both ordinary tool admission and active response use this verifier. It does
//! not authenticate capability admission, mutate replay state, or collect votes.

use super::{
    ThresholdApprovalProposal, ThresholdApprovalRequirement, ThresholdApprovalRequirementResolver,
};
use crate::approval::{ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStoreError};
use chio_core::canonical_json_bytes;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, VerifiedApprovalSetBody,
};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{sha256_hex, PublicKey, SigningAlgorithm};
use std::collections::BTreeSet;

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
    /// Policy-owned algorithm allowlist for both the proposal and every vote.
    /// Algorithm metadata must also match the actual key and signature.
    pub allowed_signing_algorithms: &'a [SigningAlgorithm],
    pub now: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ThresholdApprovalVerificationError {
    #[error("threshold approval requirement resolution failed: {0}")]
    Requirement(String),
    #[error("threshold approval verification denied: {0}")]
    Denied(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedThresholdApprovalSet {
    body: VerifiedApprovalSetBody,
    members: Vec<ApprovalReservationMember>,
}

impl VerifiedThresholdApprovalSet {
    #[must_use]
    pub fn body(&self) -> &VerifiedApprovalSetBody {
        &self.body
    }

    #[must_use]
    pub fn members(&self) -> &[ApprovalReservationMember] {
        &self.members
    }

    pub fn approval_set_hash(&self) -> Result<String, ThresholdApprovalVerificationError> {
        self.body.approval_set_hash().map_err(|error| {
            threshold_denied(&format!("verified approval set hash failed: {error}"))
        })
    }

    pub fn reservation_input(&self) -> Result<ApprovalSetReservationInput, ApprovalStoreError> {
        ApprovalSetReservationInput::new(
            self.body
                .approval_set_hash()
                .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?,
            self.members.clone(),
            self.body.proposal_deadline,
        )
    }
}

impl core::ops::Deref for VerifiedThresholdApprovalSet {
    type Target = VerifiedApprovalSetBody;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

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

/// Verify a complete threshold token set without mutating replay state.
pub fn verify_threshold_approval_set(
    input: &ThresholdApprovalVerificationInput<'_>,
    resolver: &dyn ThresholdApprovalRequirementResolver,
) -> Result<VerifiedThresholdApprovalSet, ThresholdApprovalVerificationError> {
    let token_count = input.approval_tokens.len();
    if token_count > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS {
        return Err(threshold_denied(
            "approval token set exceeds the protocol ceiling",
        ));
    }
    let requirement = resolver
        .resolve_requirement(input.policy_hash, input.server_id, input.tool_name)
        .map_err(ThresholdApprovalVerificationError::Requirement)?
        .ok_or_else(|| threshold_denied("threshold approval requirement is unavailable"))?;
    verify_threshold_approval_set_with_requirement(input, &requirement)
}

/// Verify against one policy resolution already obtained by the kernel's
/// negotiated request path. Do not resolve mutable policy a second time.
pub(crate) fn verify_threshold_approval_set_with_requirement(
    input: &ThresholdApprovalVerificationInput<'_>,
    requirement: &ThresholdApprovalRequirement,
) -> Result<VerifiedThresholdApprovalSet, ThresholdApprovalVerificationError> {
    let token_count = input.approval_tokens.len();
    if token_count > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS {
        return Err(threshold_denied(
            "approval token set exceeds the protocol ceiling",
        ));
    }
    requirement
        .validate()
        .map_err(|error| threshold_denied(&error))?;
    if requirement.policy_hash != input.policy_hash
        || token_count > requirement.eligible_approvers.len()
        || token_count < usize::try_from(requirement.threshold).unwrap_or(usize::MAX)
    {
        return Err(threshold_denied(
            "approval token set does not satisfy policy quorum",
        ));
    }

    let proposal = input.proposal;
    let body = &proposal.body;
    let proposal_algorithm = proposal.algorithm.unwrap_or_default();
    if !input
        .allowed_signing_algorithms
        .contains(&proposal_algorithm)
        || body.policy_authority.algorithm() != proposal_algorithm
        || proposal.signature.algorithm() != proposal_algorithm
    {
        return Err(threshold_denied(
            "threshold proposal algorithm is not permitted or consistent",
        ));
    }
    if !input
        .trusted_policy_authorities
        .contains(&body.policy_authority)
        || !proposal.verify_signature().map_err(|error| {
            threshold_denied(&format!("threshold proposal signature failed: {error}"))
        })?
    {
        return Err(threshold_denied("threshold proposal signer is not trusted"));
    }
    if body.request_id != input.request_id
        || body.governed_intent_hash != input.governed_intent_hash
        || &body.subject != input.subject
        || body.authorizing_capability_digest != input.authorization_capability_hash
        || body.policy_hash != input.policy_hash
        || body.threshold != requirement.threshold
        || body.eligible_set_digest != requirement.eligible_set_digest
    {
        return Err(threshold_denied(
            "threshold proposal does not match the request, capability, or active policy",
        ));
    }
    let expected_deadline = body
        .proposal_created_at
        .checked_add(requirement.timeout_seconds)
        .ok_or_else(|| threshold_denied("threshold proposal deadline overflowed"))?
        .min(input.authorizing_capability_expires_at)
        .min(input.governed_operation_expires_at);
    if body.proposal_deadline != expected_deadline
        || input.now < body.proposal_created_at
        || input.now >= body.proposal_deadline
    {
        return Err(threshold_denied(
            "threshold proposal window is invalid for the active policy",
        ));
    }

    let proposal_hash = proposal
        .artifact_digest()
        .map_err(|error| threshold_denied(&format!("threshold proposal hash failed: {error}")))?;
    let eligible = requirement
        .eligible_approvers
        .iter()
        .map(|approver| approver.public_key.to_hex())
        .collect::<BTreeSet<_>>();
    let mut token_ids = BTreeSet::new();
    let mut token_digests = BTreeSet::new();
    let mut signers = BTreeSet::new();
    let mut members = Vec::with_capacity(token_count);
    for token in input.approval_tokens {
        if token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str())
            || token.request_id != input.request_id
            || token.governed_intent_hash != input.governed_intent_hash
            || &token.subject != input.subject
            || token.decision != GovernedApprovalDecision::Approved
            || token.id.is_empty()
            || token.id.trim() != token.id
            || token.issued_at < body.proposal_created_at
            || token.issued_at >= body.proposal_deadline
            || input.now < token.issued_at
            || token.expires_at <= token.issued_at
            || token.expires_at > body.proposal_deadline
            || input.now >= token.expires_at
        {
            return Err(threshold_denied(
                "approval token binding or validity is invalid",
            ));
        }
        let algorithm = token.algorithm.unwrap_or_default();
        if !input.allowed_signing_algorithms.contains(&algorithm)
            || token.approver.algorithm() != algorithm
            || token.signature.algorithm() != algorithm
            || !eligible.contains(&token.approver.to_hex())
            || !token.verify_signature().map_err(|error| {
                threshold_denied(&format!("approval token signature failed: {error}"))
            })?
        {
            return Err(threshold_denied("approval token signer is not valid"));
        }
        let digest = token
            .token_digest()
            .map_err(|error| threshold_denied(&format!("approval token digest failed: {error}")))?;
        if !token_ids.insert(token.id.clone())
            || !token_digests.insert(digest.clone())
            || !signers.insert(token.approver.to_hex())
        {
            return Err(threshold_denied("approval token set contains a duplicate"));
        }
        members.push(
            ApprovalReservationMember::new(token.id.clone(), digest).map_err(|error| {
                threshold_denied(&format!("approval replay member is invalid: {error}"))
            })?,
        );
    }
    members.sort_unstable_by(|left, right| {
        left.token_digest()
            .cmp(right.token_digest())
            .then_with(|| left.token_id().cmp(right.token_id()))
    });
    let body = VerifiedApprovalSetBody::new(token_digests.into_iter().collect(), proposal)
        .map_err(|error| threshold_denied(&format!("verified approval set failed: {error}")))?;
    Ok(VerifiedThresholdApprovalSet { body, members })
}

fn threshold_denied(reason: &str) -> ThresholdApprovalVerificationError {
    ThresholdApprovalVerificationError::Denied(reason.to_string())
}
