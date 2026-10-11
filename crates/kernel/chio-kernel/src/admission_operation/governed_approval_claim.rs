//! Operation-owned approval replay intent and history. These are bounded data,
//! not proof of a trusted signer, a live operation lease or dispatch permission.

use super::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationId,
    AdmissionOperationStoreError as Error,
};
use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
use serde::{Deserialize, Serialize};

pub const MAX_GOVERNED_APPROVAL_CLAIM_EPISODES: usize = 128;
const MAX_UNIX_SECS: u64 = 9_007_199_254_740;
const MAX_APPROVAL_TTL_SECS: u64 = 3600;

/// Independently configured migration generation, not an authority credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalAuthorityBindingV1 {
    approval_authority_id: AdmissionIdentifier,
    expectation_id: AdmissionIdentifier,
}
impl GovernedApprovalAuthorityBindingV1 {
    pub fn new(
        approval_authority_id: AdmissionIdentifier,
        expectation_id: AdmissionIdentifier,
    ) -> Self {
        Self {
            approval_authority_id,
            expectation_id,
        }
    }
    pub fn approval_authority_id(&self) -> &AdmissionIdentifier {
        &self.approval_authority_id
    }
    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedApprovalClaimPhase {
    NoncePreflight,
    Dispatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedApprovalClaimDisposition {
    ReservedBeforeDispatch,
    ReleasedBeforeDispatch,
    RetainedAfterDispatchCommit,
}

/// A non-executable commitment to an approval token. No reusable signature is
/// retained here. Trust, policy and capability verification remain mandatory
/// at the configured kernel boundary before supplying a claim intent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedApprovalCredentialV1 {
    pub subject_id: AdmissionIdentifier,
    pub request_id: AdmissionIdentifier,
    pub intent_hash: AdmissionDigest,
    pub token_digest: AdmissionDigest,
    pub approver_id: AdmissionIdentifier,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}
impl GovernedApprovalCredentialV1 {
    /// Check the artifact itself, not whether its signer is a trusted authority.
    /// The originating kernel must perform its configured trust checks first.
    pub fn from_token(token: &GovernedApprovalToken) -> Result<Self, Error> {
        if token.decision != GovernedApprovalDecision::Approved
            || !token.verify_signature().map_err(invalid)?
        {
            return Err(invalid(
                "approval artifact does not carry a valid approved signature",
            ));
        }
        let value = Self {
            subject_id: AdmissionIdentifier::try_new("approval_subject", token.subject.to_hex())?,
            request_id: AdmissionIdentifier::try_new("approval_request", &token.request_id)?,
            intent_hash: AdmissionDigest::try_new("approval_intent", &token.governed_intent_hash)?,
            token_digest: AdmissionDigest::try_new(
                "approval_token",
                token.artifact_digest().map_err(invalid)?,
            )?,
            approver_id: AdmissionIdentifier::try_new(
                "approval_approver",
                token.approver.to_hex(),
            )?,
            issued_at_unix_secs: token.issued_at,
            expires_at_unix_secs: token.expires_at,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.expires_at_unix_secs > MAX_UNIX_SECS
            || self.expires_at_unix_secs <= self.issued_at_unix_secs
            || self.expires_at_unix_secs - self.issued_at_unix_secs > MAX_APPROVAL_TTL_SECS
            || self.subject_id.as_str()
                == super::governed_approval_replay::LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT
        {
            return Err(invalid("invalid approval lifetime or reserved subject"));
        }
        Ok(())
    }
    pub fn validate_at(&self, authority_time_unix_ms: u64) -> Result<(), Error> {
        self.validate()?;
        let seconds = authority_time_unix_ms / 1000;
        if seconds < self.issued_at_unix_secs || seconds >= self.expires_at_unix_secs {
            return Err(invalid("approval is not valid at the authority clock"));
        }
        Ok(())
    }
}

/// Intent emitted only after complete configured approval validation. Decoding
/// or constructing these fields establishes neither trust nor ownership.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "GovernedApprovalClaimIntentInput"
)]
pub struct GovernedApprovalClaimIntentV1 {
    episode_id: AdmissionIdentifier,
    approval_authority_id: AdmissionIdentifier,
    expectation_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    grant_index: u32,
    phase: GovernedApprovalClaimPhase,
    credential: GovernedApprovalCredentialV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedApprovalClaimIntentInput {
    pub episode_id: AdmissionIdentifier,
    pub approval_authority_id: AdmissionIdentifier,
    pub expectation_id: AdmissionIdentifier,
    pub request_binding_hash: AdmissionDigest,
    pub grant_index: u32,
    pub phase: GovernedApprovalClaimPhase,
    pub credential: GovernedApprovalCredentialV1,
}
impl TryFrom<GovernedApprovalClaimIntentInput> for GovernedApprovalClaimIntentV1 {
    type Error = Error;
    fn try_from(input: GovernedApprovalClaimIntentInput) -> Result<Self, Error> {
        Self::new(input)
    }
}
impl GovernedApprovalClaimIntentV1 {
    pub fn new(input: GovernedApprovalClaimIntentInput) -> Result<Self, Error> {
        let value = Self {
            episode_id: input.episode_id,
            approval_authority_id: input.approval_authority_id,
            expectation_id: input.expectation_id,
            request_binding_hash: input.request_binding_hash,
            grant_index: input.grant_index,
            phase: input.phase,
            credential: input.credential,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.credential.validate()
    }
    pub fn episode_id(&self) -> &AdmissionIdentifier {
        &self.episode_id
    }
    pub fn approval_authority_id(&self) -> &AdmissionIdentifier {
        &self.approval_authority_id
    }
    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation_id
    }
    pub fn request_binding_hash(&self) -> &AdmissionDigest {
        &self.request_binding_hash
    }
    pub fn grant_index(&self) -> u32 {
        self.grant_index
    }
    pub fn phase(&self) -> GovernedApprovalClaimPhase {
        self.phase
    }
    pub fn credential(&self) -> &GovernedApprovalCredentialV1 {
        &self.credential
    }
}
impl std::fmt::Debug for GovernedApprovalClaimIntentV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernedApprovalClaimIntentV1")
            .field("episode_id", &self.episode_id)
            .field("phase", &self.phase)
            .field("grant_index", &self.grant_index)
            .finish_non_exhaustive()
    }
}

/// Exact historical lookup data. Release still requires a live operation lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedApprovalClaimReferenceV1 {
    operation_id: AdmissionOperationId,
    episode_id: AdmissionIdentifier,
    claim_digest: AdmissionDigest,
}
impl GovernedApprovalClaimReferenceV1 {
    pub fn new(
        operation_id: AdmissionOperationId,
        episode_id: AdmissionIdentifier,
        claim_digest: AdmissionDigest,
    ) -> Self {
        Self {
            operation_id,
            episode_id,
            claim_digest,
        }
    }
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }
    pub fn episode_id(&self) -> &AdmissionIdentifier {
        &self.episode_id
    }
    pub fn claim_digest(&self) -> &AdmissionDigest {
        &self.claim_digest
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedApprovalClaimHistoryV1 {
    pub reference: GovernedApprovalClaimReferenceV1,
    pub intent: GovernedApprovalClaimIntentV1,
    pub disposition: GovernedApprovalClaimDisposition,
}
fn invalid(detail: impl std::fmt::Display) -> Error {
    Error::Invariant(format!("governed approval claim: {detail}"))
}
