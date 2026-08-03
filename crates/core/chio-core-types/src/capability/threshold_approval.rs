//! Policy-owned threshold approval requirements and resolver contracts.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{
    is_default_optional_algorithm, sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm,
    SigningBackend,
};
use crate::error::{Error, Result as CoreResult};

/// Default lifetime for a threshold approval proposal.
pub const DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS: u64 = 900;

/// Hard upper bound for a threshold approval proposal lifetime.
pub const MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS: u64 = 3_600;

/// Domain separator for the policy-owned eligible approver set.
pub const CHIO_APPROVER_SET_DIGEST_DOMAIN: &str = "chio.approver-set.v1\0";

/// Domain for signing canonical threshold approval proposal bodies.
pub const CHIO_THRESHOLD_APPROVAL_PROPOSAL_SIGNATURE_DOMAIN: &str =
    "chio.threshold-approval-proposal.v1\0";

/// Schema carried by signed threshold approval proposal bodies.
pub const CHIO_THRESHOLD_APPROVAL_PROPOSAL_SCHEMA: &str = "chio.threshold-approval-proposal.v1";

/// Domain for hashing a verified, order-independent approval set body.
pub const CHIO_VERIFIED_APPROVAL_SET_DOMAIN: &str = "chio.verified-approval-set.v1\0";

/// Schema carried by verified threshold approval set bodies.
pub const CHIO_VERIFIED_APPROVAL_SET_SCHEMA: &str = "chio.verified-approval-set.v1";

/// Hard ceiling for approval tokens supplied for one governed request.
pub const MAX_THRESHOLD_APPROVAL_TOKENS: usize = 32;

/// Maximum UTF-8 byte length for threshold request, proposal, token, and approver IDs.
pub const MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES: usize = 256;

/// Exact request identity passed to the requirement resolver after policy matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThresholdApprovalRequest {
    request_id: String,
    server_id: String,
    tool_name: String,
}

/// Policy-authority-signable proposal binding a threshold requirement to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThresholdApprovalProposalBody {
    schema: String,
    proposal_id: String,
    request_id: String,
    governed_intent_hash: String,
    subject: PublicKey,
    authorization_capability_hash: String,
    policy_hash: String,
    required: u32,
    eligible_set_digest: String,
    proposal_created_at: u64,
    proposal_deadline: u64,
}

/// Signed threshold proposal envelope issued by the authenticated policy authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThresholdApprovalProposal {
    body: ThresholdApprovalProposalBody,
    policy_authority: PublicKey,
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    algorithm: Option<SigningAlgorithm>,
    signature: Signature,
}

/// Canonical, order-independent projection of approval tokens accepted for a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedApprovalSetBody {
    schema: String,
    canonical_token_digests: Vec<String>,
    policy_hash: String,
    required: u32,
    eligible_set_digest: String,
    request_id: String,
    governed_intent_hash: String,
    subject: PublicKey,
    authorization_capability_hash: String,
    threshold_proposal_hash: String,
    proposal_id: String,
    proposal_created_at: u64,
    proposal_deadline: u64,
}

impl ThresholdApprovalProposalBody {
    /// Construct a proposal and derive its exclusive deadline from all authority bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        request_id: impl Into<String>,
        governed_intent_hash: impl Into<String>,
        subject: PublicKey,
        authorization_capability_hash: impl Into<String>,
        policy_hash: impl Into<String>,
        required: u32,
        eligible_set_digest: impl Into<String>,
        proposal_created_at: u64,
        compiled_timeout_seconds: u64,
        authorizing_capability_expires_at: u64,
        governed_operation_expires_at: u64,
    ) -> CoreResult<Self> {
        if compiled_timeout_seconds == 0
            || compiled_timeout_seconds > MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS
        {
            return Err(invalid_artifact(
                "proposal timeout is zero or exceeds the protocol maximum",
            ));
        }
        let timeout_deadline = proposal_created_at
            .checked_add(compiled_timeout_seconds)
            .ok_or_else(|| invalid_artifact("proposal deadline arithmetic overflowed"))?;
        let proposal_deadline = timeout_deadline
            .min(authorizing_capability_expires_at)
            .min(governed_operation_expires_at);
        let proposal = Self {
            schema: CHIO_THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: proposal_id.into(),
            request_id: request_id.into(),
            governed_intent_hash: governed_intent_hash.into(),
            subject,
            authorization_capability_hash: authorization_capability_hash.into(),
            policy_hash: policy_hash.into(),
            required,
            eligible_set_digest: eligible_set_digest.into(),
            proposal_created_at,
            proposal_deadline,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    /// Validate structural invariants after construction or deserialization.
    pub fn validate(&self) -> CoreResult<()> {
        if self.schema != CHIO_THRESHOLD_APPROVAL_PROPOSAL_SCHEMA {
            return Err(invalid_artifact("unsupported threshold proposal schema"));
        }
        validate_request_component_for_artifact(&self.proposal_id, "proposal_id")?;
        validate_request_component_for_artifact(&self.request_id, "request_id")?;
        validate_digest(&self.governed_intent_hash, "governed_intent_hash")?;
        validate_digest(
            &self.authorization_capability_hash,
            "authorization_capability_hash",
        )?;
        validate_digest(&self.policy_hash, "policy_hash")?;
        validate_digest(&self.eligible_set_digest, "eligible_set_digest")?;
        if self.required == 0
            || usize::try_from(self.required)
                .map_or(true, |required| required > MAX_THRESHOLD_APPROVAL_TOKENS)
        {
            return Err(invalid_artifact(
                "proposal threshold is zero or exceeds the token ceiling",
            ));
        }
        let lifetime = self
            .proposal_deadline
            .checked_sub(self.proposal_created_at)
            .ok_or_else(|| invalid_artifact("proposal deadline precedes its creation time"))?;
        if lifetime == 0 || lifetime > MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS {
            return Err(invalid_artifact(
                "proposal deadline is empty or exceeds the protocol maximum",
            ));
        }
        Ok(())
    }

    /// Exact domain-separated canonical bytes signed by the policy authority.
    pub fn signing_bytes(&self) -> CoreResult<Vec<u8>> {
        self.validate()?;
        domain_separated_bytes(CHIO_THRESHOLD_APPROVAL_PROPOSAL_SIGNATURE_DOMAIN, self)
    }

    #[must_use]
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn subject(&self) -> &PublicKey {
        &self.subject
    }

    #[must_use]
    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    #[must_use]
    pub fn required(&self) -> u32 {
        self.required
    }

    #[must_use]
    pub fn eligible_set_digest(&self) -> &str {
        &self.eligible_set_digest
    }

    #[must_use]
    pub fn proposal_created_at(&self) -> u64 {
        self.proposal_created_at
    }

    #[must_use]
    pub fn proposal_deadline(&self) -> u64 {
        self.proposal_deadline
    }
}

impl ThresholdApprovalProposal {
    /// Sign a validated proposal with an Ed25519 policy authority.
    pub fn sign(body: ThresholdApprovalProposalBody, keypair: &Keypair) -> CoreResult<Self> {
        let signing_bytes = body.signing_bytes()?;
        Ok(Self {
            body,
            policy_authority: keypair.public_key(),
            algorithm: None,
            signature: keypair.sign(&signing_bytes),
        })
    }

    /// Sign a validated proposal with an arbitrary supported signing backend.
    pub fn sign_with_backend(
        body: ThresholdApprovalProposalBody,
        backend: &dyn SigningBackend,
    ) -> CoreResult<Self> {
        let signing_bytes = body.signing_bytes()?;
        let outcome = backend.sign_bytes_with_identity(&signing_bytes)?;
        let policy_authority = outcome.public_key;
        let algorithm = outcome.algorithm;
        let signature = outcome.signature;
        if signature.algorithm() != algorithm
            || !policy_authority.verify(&signing_bytes, &signature)
        {
            return Err(Error::InvalidSignature(
                "threshold proposal backend returned an invalid signature".into(),
            ));
        }
        Ok(Self {
            body,
            policy_authority,
            algorithm: (!algorithm.is_default()).then_some(algorithm),
            signature,
        })
    }

    /// Verify the proposal's structural bounds, algorithm binding, and signature.
    pub fn verify_signature(&self) -> CoreResult<bool> {
        let expected_algorithm = self.algorithm.unwrap_or_default();
        if self.policy_authority.algorithm() != expected_algorithm
            || self.signature.algorithm() != expected_algorithm
        {
            return Ok(false);
        }
        Ok(self
            .policy_authority
            .verify(&self.body.signing_bytes()?, &self.signature))
    }

    /// Hash the canonical signed proposal body under its signature domain.
    pub fn proposal_hash(&self) -> CoreResult<String> {
        Ok(sha256_hex(&self.body.signing_bytes()?))
    }

    #[must_use]
    pub fn body(&self) -> &ThresholdApprovalProposalBody {
        &self.body
    }

    #[must_use]
    pub fn policy_authority(&self) -> &PublicKey {
        &self.policy_authority
    }

    #[must_use]
    pub fn algorithm(&self) -> Option<SigningAlgorithm> {
        self.algorithm
    }

    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl VerifiedApprovalSetBody {
    /// Construct the canonical set projection from already verified token digests.
    pub fn new(
        mut canonical_token_digests: Vec<String>,
        proposal: &ThresholdApprovalProposal,
    ) -> CoreResult<Self> {
        if !proposal.verify_signature()? {
            return Err(Error::SignatureVerificationFailed);
        }
        let body = proposal.body();
        if canonical_token_digests.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
            return Err(invalid_artifact(
                "approval token set exceeds the protocol ceiling",
            ));
        }
        if canonical_token_digests.len()
            < usize::try_from(body.required)
                .map_err(|_| invalid_artifact("proposal threshold does not fit this platform"))?
        {
            return Err(invalid_artifact(
                "approval token set does not satisfy threshold",
            ));
        }
        for digest in &canonical_token_digests {
            validate_digest(digest, "token_digest")?;
        }
        canonical_token_digests.sort_unstable();
        if canonical_token_digests
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(invalid_artifact(
                "approval token set contains a duplicate digest",
            ));
        }
        Ok(Self {
            schema: CHIO_VERIFIED_APPROVAL_SET_SCHEMA.to_string(),
            canonical_token_digests,
            policy_hash: body.policy_hash.clone(),
            required: body.required,
            eligible_set_digest: body.eligible_set_digest.clone(),
            request_id: body.request_id.clone(),
            governed_intent_hash: body.governed_intent_hash.clone(),
            subject: body.subject.clone(),
            authorization_capability_hash: body.authorization_capability_hash.clone(),
            threshold_proposal_hash: proposal.proposal_hash()?,
            proposal_id: body.proposal_id.clone(),
            proposal_created_at: body.proposal_created_at,
            proposal_deadline: body.proposal_deadline,
        })
    }

    /// Validate canonical ordering and proposal-derived structural fields.
    pub fn validate(&self) -> CoreResult<()> {
        if self.schema != CHIO_VERIFIED_APPROVAL_SET_SCHEMA {
            return Err(invalid_artifact("unsupported verified approval set schema"));
        }
        if self.canonical_token_digests.len() > MAX_THRESHOLD_APPROVAL_TOKENS
            || self.canonical_token_digests.len()
                < usize::try_from(self.required).map_err(|_| {
                    invalid_artifact("approval threshold does not fit this platform")
                })?
        {
            return Err(invalid_artifact("approval token set has an invalid size"));
        }
        if self.required == 0 {
            return Err(invalid_artifact("approval threshold must be non-zero"));
        }
        for digest in &self.canonical_token_digests {
            validate_digest(digest, "token_digest")?;
        }
        if self
            .canonical_token_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid_artifact(
                "approval token digests must be strictly sorted",
            ));
        }
        validate_digest(&self.policy_hash, "policy_hash")?;
        validate_digest(&self.eligible_set_digest, "eligible_set_digest")?;
        validate_digest(&self.governed_intent_hash, "governed_intent_hash")?;
        validate_digest(
            &self.authorization_capability_hash,
            "authorization_capability_hash",
        )?;
        validate_digest(&self.threshold_proposal_hash, "threshold_proposal_hash")?;
        validate_request_component_for_artifact(&self.proposal_id, "proposal_id")?;
        validate_request_component_for_artifact(&self.request_id, "request_id")?;
        let lifetime = self
            .proposal_deadline
            .checked_sub(self.proposal_created_at)
            .ok_or_else(|| invalid_artifact("proposal deadline precedes its creation time"))?;
        if lifetime == 0 || lifetime > MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS {
            return Err(invalid_artifact(
                "approval set carries an invalid proposal window",
            ));
        }
        Ok(())
    }

    /// Validate every proposal-derived field against the authenticated proposal.
    pub fn validate_against_proposal(
        &self,
        proposal: &ThresholdApprovalProposal,
    ) -> CoreResult<()> {
        self.validate()?;
        if !proposal.verify_signature()? {
            return Err(Error::SignatureVerificationFailed);
        }
        let body = proposal.body();
        let proposal_hash = proposal.proposal_hash()?;
        if self.policy_hash != body.policy_hash
            || self.required != body.required
            || self.eligible_set_digest != body.eligible_set_digest
            || self.request_id != body.request_id
            || self.governed_intent_hash != body.governed_intent_hash
            || self.subject != body.subject
            || self.authorization_capability_hash != body.authorization_capability_hash
            || self.threshold_proposal_hash != proposal_hash
            || self.proposal_id != body.proposal_id
            || self.proposal_created_at != body.proposal_created_at
            || self.proposal_deadline != body.proposal_deadline
        {
            return Err(invalid_artifact(
                "verified approval set does not match threshold proposal",
            ));
        }
        Ok(())
    }

    /// Hash the complete canonical set body under the protocol domain.
    pub fn approval_set_hash(&self) -> CoreResult<String> {
        self.validate()?;
        domain_separated_hash(CHIO_VERIFIED_APPROVAL_SET_DOMAIN, self)
    }

    #[must_use]
    pub fn token_digests(&self) -> &[String] {
        &self.canonical_token_digests
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    #[must_use]
    pub fn required(&self) -> u32 {
        self.required
    }

    #[must_use]
    pub fn eligible_set_digest(&self) -> &str {
        &self.eligible_set_digest
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn subject(&self) -> &PublicKey {
        &self.subject
    }

    #[must_use]
    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub fn threshold_proposal_hash(&self) -> &str {
        &self.threshold_proposal_hash
    }

    #[must_use]
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    #[must_use]
    pub fn proposal_created_at(&self) -> u64 {
        self.proposal_created_at
    }

    #[must_use]
    pub fn proposal_deadline(&self) -> u64 {
        self.proposal_deadline
    }
}

impl ThresholdApprovalRequest {
    /// Construct a non-empty matched request identity.
    pub fn new(
        request_id: impl Into<String>,
        server_id: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Result<Self, ThresholdApprovalRequirementError> {
        let request = Self {
            request_id: request_id.into(),
            server_id: server_id.into(),
            tool_name: tool_name.into(),
        };
        validate_request_component(&request.request_id, "request_id")?;
        validate_request_component(&request.server_id, "server_id")?;
        validate_request_component(&request.tool_name, "tool_name")?;
        Ok(request)
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
}

/// Immutable threshold requirement compiled from authenticated policy state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdApprovalRequirement {
    required: u32,
    eligible: BTreeMap<String, PublicKey>,
    proposal_timeout_seconds: u64,
    eligible_set_digest: String,
    policy_hash: String,
    approver_directory_version: u64,
}

impl ThresholdApprovalRequirement {
    /// Validate and construct a policy-owned requirement.
    pub fn new(
        required: u32,
        eligible: BTreeMap<String, PublicKey>,
        proposal_timeout_seconds: u64,
        policy_hash: impl Into<String>,
        approver_directory_version: u64,
    ) -> Result<Self, ThresholdApprovalRequirementError> {
        if eligible.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
            return Err(
                ThresholdApprovalRequirementError::TooManyEligibleApprovers {
                    eligible: eligible.len(),
                    maximum: MAX_THRESHOLD_APPROVAL_TOKENS,
                },
            );
        }
        if required == 0 {
            return Err(ThresholdApprovalRequirementError::ZeroThreshold);
        }
        if usize::try_from(required).map_or(true, |required| required > eligible.len()) {
            return Err(ThresholdApprovalRequirementError::UnsatisfiableThreshold {
                required,
                eligible: eligible.len(),
            });
        }
        if proposal_timeout_seconds == 0
            || proposal_timeout_seconds > MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS
        {
            return Err(ThresholdApprovalRequirementError::InvalidTimeout {
                timeout_seconds: proposal_timeout_seconds,
                maximum_seconds: MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
            });
        }
        if approver_directory_version == 0 {
            return Err(ThresholdApprovalRequirementError::InvalidDirectoryVersion);
        }

        let policy_hash = policy_hash.into();
        if !is_lowercase_sha256_hex(&policy_hash) {
            return Err(ThresholdApprovalRequirementError::InvalidPolicyHash);
        }

        let mut key_fingerprints = BTreeSet::new();
        for (approver_id, public_key) in &eligible {
            validate_request_component(approver_id, "approver_id")?;
            let fingerprint = public_key.to_hex();
            if !key_fingerprints.insert(fingerprint) {
                return Err(ThresholdApprovalRequirementError::DuplicatePublicKey);
            }
        }

        let eligible_set_digest = eligible_set_digest(&eligible)?;
        Ok(Self {
            required,
            eligible,
            proposal_timeout_seconds,
            eligible_set_digest,
            policy_hash,
            approver_directory_version,
        })
    }

    #[must_use]
    pub fn required(&self) -> u32 {
        self.required
    }

    #[must_use]
    pub fn eligible(&self) -> &BTreeMap<String, PublicKey> {
        &self.eligible
    }

    #[must_use]
    pub fn proposal_timeout_seconds(&self) -> u64 {
        self.proposal_timeout_seconds
    }

    #[must_use]
    pub fn eligible_set_digest(&self) -> &str {
        &self.eligible_set_digest
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    #[must_use]
    pub fn approver_directory_version(&self) -> u64 {
        self.approver_directory_version
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EligibleApproverDigestEntry<'a> {
    approver_id: &'a str,
    public_key: &'a PublicKey,
}

fn eligible_set_digest(
    eligible: &BTreeMap<String, PublicKey>,
) -> Result<String, ThresholdApprovalRequirementError> {
    let entries = eligible
        .iter()
        .map(|(approver_id, public_key)| EligibleApproverDigestEntry {
            approver_id,
            public_key,
        })
        .collect::<Vec<_>>();
    let canonical = canonical_json_bytes(&entries)
        .map_err(|error| ThresholdApprovalRequirementError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(CHIO_APPROVER_SET_DIGEST_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(CHIO_APPROVER_SET_DIGEST_DOMAIN.as_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn domain_separated_bytes<T: Serialize>(domain: &str, value: &T) -> CoreResult<Vec<u8>> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

fn domain_separated_hash<T: Serialize>(domain: &str, value: &T) -> CoreResult<String> {
    Ok(sha256_hex(&domain_separated_bytes(domain, value)?))
}

fn invalid_artifact(reason: &str) -> Error {
    Error::AttenuationViolation {
        reason: reason.to_string(),
    }
}

fn validate_request_component_for_artifact(value: &str, field: &'static str) -> CoreResult<()> {
    if !is_valid_identifier(value) {
        return Err(invalid_artifact(&alloc::format!(
            "threshold approval {field} is empty, unbounded, or not normalized"
        )));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> CoreResult<()> {
    if !is_lowercase_sha256_hex(value) {
        return Err(invalid_artifact(&alloc::format!(
            "threshold approval {field} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn validate_request_component(
    value: &str,
    field: &'static str,
) -> Result<(), ThresholdApprovalRequirementError> {
    if !is_valid_identifier(value) {
        return Err(ThresholdApprovalRequirementError::InvalidIdentifier { field });
    }
    Ok(())
}

fn is_valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Structural failures while constructing a threshold requirement.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThresholdApprovalRequirementError {
    #[cfg_attr(
        feature = "std",
        error("threshold eligible set has {eligible} approvers but the maximum is {maximum}")
    )]
    TooManyEligibleApprovers { eligible: usize, maximum: usize },
    #[cfg_attr(
        feature = "std",
        error("threshold approval requires at least one approver")
    )]
    ZeroThreshold,
    #[cfg_attr(
        feature = "std",
        error("threshold {required} cannot be satisfied by {eligible} eligible approvers")
    )]
    UnsatisfiableThreshold { required: u32, eligible: usize },
    #[cfg_attr(
        feature = "std",
        error("threshold approval timeout {timeout_seconds} must be between 1 and {maximum_seconds} seconds")
    )]
    InvalidTimeout {
        timeout_seconds: u64,
        maximum_seconds: u64,
    },
    #[cfg_attr(feature = "std", error("approver directory version must be non-zero"))]
    InvalidDirectoryVersion,
    #[cfg_attr(
        feature = "std",
        error("threshold approval policy hash must be lowercase SHA-256 hex")
    )]
    InvalidPolicyHash,
    #[cfg_attr(
        feature = "std",
        error("threshold approval {field} is empty or not normalized")
    )]
    InvalidIdentifier { field: &'static str },
    #[cfg_attr(
        feature = "std",
        error("threshold approval eligible set contains the same public key more than once")
    )]
    DuplicatePublicKey,
    #[cfg_attr(
        feature = "std",
        error("threshold approval eligible set canonicalization failed: {0}")
    )]
    Canonicalization(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for ThresholdApprovalRequirementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyEligibleApprovers { eligible, maximum } => write!(
                f,
                "threshold eligible set has {eligible} approvers but the maximum is {maximum}"
            ),
            Self::ZeroThreshold => write!(f, "threshold approval requires at least one approver"),
            Self::UnsatisfiableThreshold { required, eligible } => write!(
                f,
                "threshold {required} cannot be satisfied by {eligible} eligible approvers"
            ),
            Self::InvalidTimeout {
                timeout_seconds,
                maximum_seconds,
            } => write!(
                f,
                "threshold approval timeout {timeout_seconds} must be between 1 and {maximum_seconds} seconds"
            ),
            Self::InvalidDirectoryVersion => {
                write!(f, "approver directory version must be non-zero")
            }
            Self::InvalidPolicyHash => write!(
                f,
                "threshold approval policy hash must be lowercase SHA-256 hex"
            ),
            Self::InvalidIdentifier { field } => {
                write!(f, "threshold approval {field} is empty or not normalized")
            }
            Self::DuplicatePublicKey => write!(
                f,
                "threshold approval eligible set contains the same public key more than once"
            ),
            Self::Canonicalization(reason) => write!(
                f,
                "threshold approval eligible set canonicalization failed: {reason}"
            ),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for ThresholdApprovalRequirementError {}

/// Fail-closed errors returned by a trusted requirement resolver.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThresholdApprovalResolutionError {
    #[cfg_attr(feature = "std", error("threshold approval requirement is missing"))]
    Missing,
    #[cfg_attr(
        feature = "std",
        error("threshold approval policy is stale: expected {expected}, received {received}")
    )]
    StalePolicy { expected: String, received: String },
    #[cfg_attr(feature = "std", error("threshold approval resolver unavailable: {0}"))]
    Unavailable(String),
    #[cfg_attr(
        feature = "std",
        error("threshold approval resolver state is corrupt: {0}")
    )]
    Corrupt(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for ThresholdApprovalResolutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => write!(f, "threshold approval requirement is missing"),
            Self::StalePolicy { expected, received } => write!(
                f,
                "threshold approval policy is stale: expected {expected}, received {received}"
            ),
            Self::Unavailable(reason) => {
                write!(f, "threshold approval resolver unavailable: {reason}")
            }
            Self::Corrupt(reason) => {
                write!(f, "threshold approval resolver state is corrupt: {reason}")
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for ThresholdApprovalResolutionError {}

/// Trusted lookup keyed by the already matched request and current policy hash.
pub trait ThresholdApprovalRequirementResolver {
    fn resolve_threshold_approval_requirement(
        &self,
        matched_request: &ThresholdApprovalRequest,
        policy_hash: &str,
    ) -> Result<ThresholdApprovalRequirement, ThresholdApprovalResolutionError>;
}

impl<F> ThresholdApprovalRequirementResolver for F
where
    F: Fn(
        &ThresholdApprovalRequest,
        &str,
    ) -> Result<ThresholdApprovalRequirement, ThresholdApprovalResolutionError>,
{
    fn resolve_threshold_approval_requirement(
        &self,
        matched_request: &ThresholdApprovalRequest,
        policy_hash: &str,
    ) -> Result<ThresholdApprovalRequirement, ThresholdApprovalResolutionError> {
        (self)(matched_request, policy_hash)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn digest_is_independent_of_insertion_order() {
        let first = Keypair::generate().public_key();
        let second = Keypair::generate().public_key();
        let left = BTreeMap::from([
            ("first".to_string(), first.clone()),
            ("second".to_string(), second.clone()),
        ]);
        let right = BTreeMap::from([("second".to_string(), second), ("first".to_string(), first)]);
        let left = ThresholdApprovalRequirement::new(2, left, 900, "11".repeat(32), 1)
            .expect("left requirement");
        let right = ThresholdApprovalRequirement::new(2, right, 900, "11".repeat(32), 1)
            .expect("right requirement");
        assert_eq!(left.eligible_set_digest(), right.eligible_set_digest());
    }
}
