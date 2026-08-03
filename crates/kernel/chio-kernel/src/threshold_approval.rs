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

use crate::approval::{ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStoreError};
use crate::canonical_json_bytes;
use crate::security_admission_operation::{
    AdmissionOperation, AdmissionOperationKind, AdmissionRequestBindingInput,
    AdmissionRequestBindingParts, PreparedAdmissionOperation,
};

const CHIO_LEGACY_GOVERNED_APPROVAL_SET_DOMAIN: &[u8] = b"chio.legacy-governed-approval-set.v1\0";

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

/// Pure verifier output carrying both the canonical set body and its exact replay members.
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
        self.body
            .approval_set_hash()
            .map_err(|error| denied(&format!("verified approval set hash failed: {error}")))
    }

    pub fn reservation_input(&self) -> Result<ApprovalSetReservationInput, ApprovalStoreError> {
        ApprovalSetReservationInput::new(
            self.body
                .approval_set_hash()
                .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?,
            self.members.clone(),
            self.body.proposal_deadline(),
        )
    }
}

impl core::ops::Deref for VerifiedThresholdApprovalSet {
    type Target = VerifiedApprovalSetBody;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

/// Canonical approval material used by the durable governed-admission saga.
///
/// Threshold approval sets and permitted legacy one-of-one approvals are
/// normalized into this representation before any replay or budget mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedGovernedApprovalAdmission {
    request_id: String,
    authorization_capability_hash: String,
    governed_intent_hash: String,
    policy_hash: String,
    threshold_proposal_hash: Option<String>,
    approval_token_digests: Vec<String>,
    approval_set: ApprovalSetReservationInput,
}

impl VerifiedGovernedApprovalAdmission {
    pub(crate) fn from_threshold(
        verified: &VerifiedThresholdApprovalSet,
    ) -> Result<Self, ThresholdApprovalVerificationError> {
        let body = verified.body();
        body.validate()
            .map_err(|error| denied(&format!("verified approval set is invalid: {error}")))?;
        let approval_set = verified.reservation_input().map_err(|error| {
            denied(&format!(
                "threshold approval reservation is invalid: {error}"
            ))
        })?;
        Ok(Self {
            request_id: body.request_id().to_string(),
            authorization_capability_hash: body.authorization_capability_hash().to_string(),
            governed_intent_hash: body.governed_intent_hash().to_string(),
            policy_hash: body.policy_hash().to_string(),
            threshold_proposal_hash: Some(body.threshold_proposal_hash().to_string()),
            approval_token_digests: body.token_digests().to_vec(),
            approval_set,
        })
    }

    pub(crate) fn from_legacy_token(
        token: &GovernedApprovalToken,
        authorization_capability_hash: &str,
        governed_intent_hash: &str,
        policy_hash: &str,
    ) -> Result<Self, ThresholdApprovalVerificationError> {
        if token.threshold_proposal_hash.is_some() {
            return Err(denied(
                "legacy approval normalization requires a token without a threshold proposal",
            ));
        }
        if token.governed_intent_hash != governed_intent_hash {
            return Err(denied(
                "legacy approval intent binding does not match admission",
            ));
        }
        if token.decision != GovernedApprovalDecision::Approved {
            return Err(denied("legacy approval token does not approve admission"));
        }
        let token_digest = token
            .token_digest()
            .map_err(|error| denied(&format!("legacy approval token digest failed: {error}")))?;
        let member = ApprovalReservationMember::new(token.id.clone(), token_digest.clone())
            .map_err(|error| denied(&format!("legacy approval member is invalid: {error}")))?;
        let canonical = canonical_json_bytes(&serde_json::json!({
            "request_id": &token.request_id,
            "governed_intent_hash": governed_intent_hash,
            "authorization_capability_hash": authorization_capability_hash,
            "policy_hash": policy_hash,
            "member": {
                "token_id": &token.id,
                "token_digest": &token_digest,
            },
            "expires_at": token.expires_at,
        }))
        .map_err(|error| {
            denied(&format!(
                "legacy approval set canonicalization failed: {error}"
            ))
        })?;
        let mut preimage =
            Vec::with_capacity(CHIO_LEGACY_GOVERNED_APPROVAL_SET_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(CHIO_LEGACY_GOVERNED_APPROVAL_SET_DOMAIN);
        preimage.extend_from_slice(&canonical);
        let approval_set =
            ApprovalSetReservationInput::new(sha256_hex(&preimage), vec![member], token.expires_at)
                .map_err(|error| {
                    denied(&format!("legacy approval reservation is invalid: {error}"))
                })?;
        Ok(Self {
            request_id: token.request_id.clone(),
            authorization_capability_hash: authorization_capability_hash.to_string(),
            governed_intent_hash: governed_intent_hash.to_string(),
            policy_hash: policy_hash.to_string(),
            threshold_proposal_hash: None,
            approval_token_digests: vec![token_digest],
            approval_set,
        })
    }

    #[must_use]
    pub(crate) fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub(crate) fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub(crate) fn approval_set_hash(&self) -> &str {
        self.approval_set.approval_set_hash()
    }
}

/// Explicit inputs for deriving one governed tool admission identity.
///
/// `request_fingerprint_hash` is the kernel-derived, domain-separated digest
/// of the complete request, not an argument-only hash.
pub(crate) struct GovernedToolAdmissionOperationInput<'a> {
    pub(crate) coordinator_authority_id: &'a str,
    pub(crate) request_id: &'a str,
    pub(crate) capability_id: &'a str,
    pub(crate) authorization_capability_hash: &'a str,
    pub(crate) request_fingerprint_hash: &'a str,
    pub(crate) governed_intent_hash: &'a str,
    pub(crate) policy_hash: &'a str,
    pub(crate) verified_approval: &'a VerifiedGovernedApprovalAdmission,
    pub(crate) broker_attempt_id: Option<&'a str>,
    pub(crate) budget_hold_id: Option<&'a str>,
    pub(crate) supplemental_authorization_reference: Option<&'a str>,
    pub(crate) supplemental_authorization_digest: Option<&'a str>,
    pub(crate) execution_nonce_id: Option<&'a str>,
    pub(crate) coordinator_lease_epoch: u64,
}

/// Deterministic operation plus the exact verified replay members it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedGovernedToolAdmission {
    operation: AdmissionOperation,
    approval_set: ApprovalSetReservationInput,
}

impl PreparedGovernedToolAdmission {
    pub(crate) fn from_parts(
        operation: AdmissionOperation,
        approval_set: ApprovalSetReservationInput,
    ) -> Result<Self, ThresholdApprovalVerificationError> {
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.state()
                != crate::security_admission_operation::AdmissionOperationState::Prepared
            || operation.approval_set_hash() != Some(approval_set.approval_set_hash())
        {
            return Err(denied(
                "prepared governed operation does not match its approval reservation",
            ));
        }
        Ok(Self {
            operation,
            approval_set,
        })
    }

    #[must_use]
    pub fn operation(&self) -> &AdmissionOperation {
        &self.operation
    }

    #[must_use]
    pub fn approval_set(&self) -> &ApprovalSetReservationInput {
        &self.approval_set
    }

    #[must_use]
    pub fn into_parts(self) -> (AdmissionOperation, ApprovalSetReservationInput) {
        (self.operation, self.approval_set)
    }
}

/// Derive the stable governed operation identity before any replay or budget mutation.
pub(crate) fn prepare_governed_tool_admission_operation(
    input: GovernedToolAdmissionOperationInput<'_>,
) -> Result<PreparedGovernedToolAdmission, ThresholdApprovalVerificationError> {
    let budget_hold_id = input
        .budget_hold_id
        .ok_or_else(|| denied("governed admission requires an operation-owned budget hold"))?;
    let verified = input.verified_approval;
    if verified.request_id != input.request_id {
        return Err(denied(
            "verified approval set request binding does not match admission",
        ));
    }
    if verified.authorization_capability_hash != input.authorization_capability_hash {
        return Err(denied(
            "verified approval set capability binding does not match admission",
        ));
    }
    if verified.governed_intent_hash != input.governed_intent_hash {
        return Err(denied(
            "verified approval set intent binding does not match admission",
        ));
    }
    if verified.policy_hash != input.policy_hash {
        return Err(denied(
            "verified approval set policy binding does not match admission",
        ));
    }

    let approval_set_hash = verified.approval_set.approval_set_hash().to_string();
    let request_binding_hash = AdmissionRequestBindingInput::new(AdmissionRequestBindingParts {
        action_hash: input.request_fingerprint_hash.to_string(),
        policy_hash: input.policy_hash.to_string(),
        governed_intent_hash: Some(input.governed_intent_hash.to_string()),
        threshold_proposal_hash: verified.threshold_proposal_hash.clone(),
        verified_approval_set_hash: Some(approval_set_hash.clone()),
        approval_token_digests: verified.approval_token_digests.clone(),
        budget_hold_reference: Some(budget_hold_id.to_string()),
        supplemental_authorization_reference: input
            .supplemental_authorization_reference
            .map(str::to_string),
        supplemental_authorization_digest: input
            .supplemental_authorization_digest
            .map(str::to_string),
        execution_nonce_reference: input.execution_nonce_id.map(str::to_string),
    })
    .and_then(|binding| binding.derive_hash())
    .map_err(|error| {
        denied(&format!(
            "governed admission request binding failed: {error}"
        ))
    })?;
    let operation = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: input.coordinator_authority_id.to_string(),
        request_id: input.request_id.to_string(),
        capability_id: input.capability_id.to_string(),
        authorization_capability_hash: input.authorization_capability_hash.to_string(),
        request_binding_hash,
        policy_hash: input.policy_hash.to_string(),
        broker_attempt_id: input.broker_attempt_id.map(str::to_string),
        budget_hold_id: Some(budget_hold_id.to_string()),
        approval_set_hash: Some(approval_set_hash),
        execution_nonce_id: input.execution_nonce_id.map(str::to_string),
        coordinator_lease_epoch: input.coordinator_lease_epoch,
    })
    .map_err(|error| denied(&format!("governed admission operation is invalid: {error}")))?;
    PreparedGovernedToolAdmission::from_parts(operation, verified.approval_set.clone())
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
) -> Result<VerifiedThresholdApprovalSet, ThresholdApprovalVerificationError> {
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
    let mut members = Vec::with_capacity(input.approval_tokens.len());

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
        if !token_digests.insert(digest.clone()) {
            return Err(denied("approval token digest is duplicated"));
        }
        members.push(
            ApprovalReservationMember::new(token.id.clone(), digest)
                .map_err(|error| denied(&format!("approval replay member is invalid: {error}")))?,
        );
        if !signer_fingerprints.insert(token.approver.to_hex()) {
            return Err(denied("approval token signer is duplicated"));
        }
    }

    members.sort_unstable_by(|left, right| {
        left.token_digest()
            .cmp(right.token_digest())
            .then_with(|| left.token_id().cmp(right.token_id()))
    });
    let body = VerifiedApprovalSetBody::new(token_digests.into_iter().collect(), proposal)
        .map_err(|error| {
            denied(&format!(
                "verified approval set construction failed: {error}"
            ))
        })?;
    Ok(VerifiedThresholdApprovalSet { body, members })
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
        ) -> Result<VerifiedThresholdApprovalSet, ThresholdApprovalVerificationError> {
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
        assert_eq!(
            left.members()
                .iter()
                .map(|member| member.token_id())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["approval-a", "approval-b"])
        );
        assert_eq!(
            left.members()
                .iter()
                .map(|member| member.token_digest())
                .collect::<Vec<_>>(),
            left.body().token_digests()
        );

        let request_fingerprint_hash = "88".repeat(32);
        let supplemental_digest = "66".repeat(32);
        let left_approval =
            VerifiedGovernedApprovalAdmission::from_threshold(&left).expect("left admission");
        let right_approval =
            VerifiedGovernedApprovalAdmission::from_threshold(&right).expect("right admission");
        let left_operation =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:0"),
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect("left operation");
        let right_operation =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &right_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:0"),
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect("right operation");
        assert_eq!(
            left_operation.operation().operation_id(),
            right_operation.operation().operation_id()
        );
        assert_eq!(
            left_operation.operation().request_binding_hash(),
            right_operation.operation().request_binding_hash()
        );
        assert_eq!(left_operation.approval_set().members(), left.members());

        let changed_supplemental_reference =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:0"),
                supplemental_authorization_reference: Some("supplemental-2"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect("changed supplemental reference");
        let changed_supplemental_digest = "77".repeat(32);
        let changed_supplemental_digest =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:0"),
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&changed_supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect("changed supplemental digest");
        assert_ne!(
            left_operation.operation().operation_id(),
            changed_supplemental_reference.operation().operation_id()
        );
        assert_ne!(
            left_operation.operation().operation_id(),
            changed_supplemental_digest.operation().operation_id()
        );

        let replayed_request_fingerprint_hash = "99".repeat(32);
        let changed_operation =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &replayed_request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:0"),
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect("changed operation");
        assert_ne!(
            left_operation.operation().operation_id(),
            changed_operation.operation().operation_id()
        );
        assert_ne!(
            left_operation.operation().request_binding_hash(),
            changed_operation.operation().request_binding_hash()
        );

        let changed_budget_operation =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:1"),
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect("changed budget operation");
        assert_ne!(
            left_operation.operation().operation_id(),
            changed_budget_operation.operation().operation_id()
        );

        let missing_budget =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &fixture.capability_hash,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: None,
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect_err("missing operation-owned budget must deny");
        assert!(missing_budget.to_string().contains("budget hold"));

        let mismatched_capability = "44".repeat(32);
        let mismatch =
            prepare_governed_tool_admission_operation(GovernedToolAdmissionOperationInput {
                coordinator_authority_id: "kernel-authority-1",
                request_id: "request-1",
                capability_id: "capability-1",
                authorization_capability_hash: &mismatched_capability,
                request_fingerprint_hash: &request_fingerprint_hash,
                governed_intent_hash: &fixture.intent_hash,
                policy_hash: fixture.requirement.policy_hash(),
                verified_approval: &left_approval,
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:request-1:capability-1:0"),
                supplemental_authorization_reference: Some("supplemental-1"),
                supplemental_authorization_digest: Some(&supplemental_digest),
                execution_nonce_id: Some("nonce-1"),
                coordinator_lease_epoch: 1,
            })
            .expect_err("mismatched capability binding must deny");
        assert!(mismatch.to_string().contains("capability binding"));
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
