use std::path::PathBuf;

use chio_core::capability::governance::{GovernedApprovalToken, GovernedTransactionIntent};
use chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS;
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, PublicKey, Signature, SigningAlgorithm};
use chio_kernel::threshold_approval::ThresholdApprovalProposal;
use chio_kernel::{
    ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
    ActiveResponseSubmissionProof,
};
use chio_secure_ipc::PeerIdentity;
use chio_security_types::ports::{
    ActionId, AdmissionArtifactRef, AttestedFindingBatchBinding, BoundedVec, Digest32, ErrorCode,
    OpaqueReceiptRef, PortError, PortErrorKind, PortResult, RecordId, RequestId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectSpec, ResponsePlan,
    MAX_RESPONSE_EFFECTS,
};
use serde::{Deserialize, Serialize};

mod client;
mod protocol;
#[cfg(test)]
mod tests;
mod transport;

pub use client::ProductionActiveResponseAuthorityClient;
pub use protocol::{
    ActiveResponseAuthorityHandler, ActiveResponseAuthorityProtocolServer,
    ActiveResponseAuthorityProtocolServerConfig,
};

pub const ACTIVE_RESPONSE_AUTHORITY_SCHEMA: &str = "chio.active-response-policy-authority.v1";
pub const ACTIVE_RESPONSE_AUTHORITY_REQUEST_DOMAIN: &str =
    "chio.active-response-policy-authority.request.v1\0";
pub const ACTIVE_RESPONSE_AUTHORITY_RESPONSE_DOMAIN: &str =
    "chio.active-response-policy-authority.response.v1\0";
pub const MAX_ACTIVE_RESPONSE_AUTHORITY_CLOCK_SKEW_SECONDS: u64 = 30;
pub const MAX_ACTIVE_RESPONSE_AUTHORITY_SOCKET_PATH_BYTES: usize = 100;
pub const MAX_ACTIVE_RESPONSE_AFFECTED_IDS: usize = 4_096;
pub const MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES: usize =
    chio_secure_ipc::DEFAULT_MAX_FRAME_BYTES;
pub const ACTIVE_RESPONSE_AUTHORITY_REJECTION_KIND: PortErrorKind = PortErrorKind::Conflict;
pub const ACTIVE_RESPONSE_AUTHORITY_TRANSIENT_REJECTION_KIND: PortErrorKind =
    PortErrorKind::Unavailable;

pub type ActiveResponseAffectedIds = BoundedVec<RecordId, MAX_ACTIVE_RESPONSE_AFFECTED_IDS>;
pub type ActiveResponseEffects = BoundedVec<ResponseEffectSpec, MAX_RESPONSE_EFFECTS>;
pub type ActiveResponseApprovalTokens =
    BoundedVec<GovernedApprovalToken, MAX_THRESHOLD_APPROVAL_TOKENS>;

/// Pinned external authority used for response selection and signed admission
/// artifacts. The broker never creates an operator capability, submission
/// proof, threshold proposal, or approval token on this authority's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionActiveResponseAuthorityFileConfig {
    pub socket_path: PathBuf,
    pub expected_peer: PeerIdentity,
    pub trusted_authority: PublicKey,
    pub timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
}

impl ProductionActiveResponseAuthorityFileConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let path_bytes = self.socket_path.as_os_str().as_encoded_bytes();
        if !self.socket_path.is_absolute()
            || path_bytes.is_empty()
            || path_bytes.len() > MAX_ACTIVE_RESPONSE_AUTHORITY_SOCKET_PATH_BYTES
            || self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > MAX_ACTIVE_RESPONSE_AUTHORITY_CLOCK_SKEW_SECONDS
            || self.expected_peer.process_id == 0
        {
            return Err(
                "active-response authority path, peer identity, deadline, or freshness bound is invalid"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "operation",
    content = "input",
    deny_unknown_fields
)]
pub enum ActiveResponseAuthorityOperation {
    Health,
    SelectPolicy {
        evidence_id: OpaqueReceiptRef,
        finding: chio_core::receipt::security::CorrelatedFindingReceiptBody,
        binding: AttestedFindingBatchBinding,
    },
    LoadArtifacts {
        response_plan: ResponsePlan,
        admission_artifact_ref: AdmissionArtifactRef,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAuthorityRequestBody {
    pub schema: String,
    pub request_id: RequestId,
    pub issued_at_unix_seconds: u64,
    pub client: PublicKey,
    pub operation: ActiveResponseAuthorityOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedActiveResponseAuthorityRequest {
    pub body: ActiveResponseAuthorityRequestBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponsePolicySelectionWire {
    pub action_id: ActionId,
    pub evidence_id: OpaqueReceiptRef,
    pub admission_artifact_ref: AdmissionArtifactRef,
    pub affected_ids: ActiveResponseAffectedIds,
    pub effects: ActiveResponseEffects,
    pub ttl_ms: u64,
    pub created_at_unix_ms: u64,
    pub operator_capability: OperatorCapabilityBinding,
    pub approval_requirement: ResponseApprovalRequirement,
    pub submitter: RecordId,
    pub reason_hash: Digest32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAdmissionArtifactsWire {
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub admission_artifact_ref: AdmissionArtifactRef,
    pub operator_capability: CapabilityToken,
    pub governed_intent: GovernedTransactionIntent,
    pub submission_proof: ActiveResponseSubmissionProof,
    pub authority_attestation: ActiveResponseArtifactAuthorityAttestation,
    pub threshold_proposal: Option<ThresholdApprovalProposal>,
    pub approval_tokens: ActiveResponseApprovalTokens,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAdmissionArtifactsDraftWire {
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub admission_artifact_ref: AdmissionArtifactRef,
    pub operator_capability: CapabilityToken,
    pub governed_intent: GovernedTransactionIntent,
    pub submission_proof: ActiveResponseSubmissionProof,
    pub authority_attestation_body: ActiveResponseArtifactAuthorityAttestationBody,
    pub threshold_proposal: Option<ThresholdApprovalProposal>,
    pub approval_tokens: ActiveResponseApprovalTokens,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveResponseAuthorityRejectionClass {
    Permanent,
    Transient,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAuthorityRejection {
    pub classification: ActiveResponseAuthorityRejectionClass,
    pub code: ErrorCode,
}

impl ActiveResponseAuthorityRejection {
    #[must_use]
    pub const fn permanent(code: ErrorCode) -> Self {
        Self {
            classification: ActiveResponseAuthorityRejectionClass::Permanent,
            code,
        }
    }

    #[must_use]
    pub const fn transient(code: ErrorCode) -> Self {
        Self {
            classification: ActiveResponseAuthorityRejectionClass::Transient,
            code,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "result",
    content = "output",
    deny_unknown_fields
)]
pub enum ActiveResponseAuthorityResult {
    Ready { protocol: String },
    Policy(Box<ActiveResponsePolicySelectionWire>),
    Artifacts(Box<ActiveResponseAdmissionArtifactsWire>),
    Rejected(ActiveResponseAuthorityRejection),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAuthorityResponseBody {
    pub schema: String,
    pub request_id: RequestId,
    pub request_digest: String,
    pub issued_at_unix_seconds: u64,
    pub authority: PublicKey,
    pub result: ActiveResponseAuthorityResult,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedActiveResponseAuthorityResponse {
    pub body: ActiveResponseAuthorityResponseBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveResponseAuthoritySigningInput<'a, T> {
    domain: &'static str,
    body: &'a T,
}

pub fn active_response_authority_request_signing_bytes(
    body: &ActiveResponseAuthorityRequestBody,
) -> PortResult<Vec<u8>> {
    canonical_json_bytes(&ActiveResponseAuthoritySigningInput {
        domain: ACTIVE_RESPONSE_AUTHORITY_REQUEST_DOMAIN,
        body,
    })
    .map_err(|_| PortError::invalid_data())
}

pub fn active_response_authority_response_signing_bytes(
    body: &ActiveResponseAuthorityResponseBody,
) -> PortResult<Vec<u8>> {
    canonical_json_bytes(&ActiveResponseAuthoritySigningInput {
        domain: ACTIVE_RESPONSE_AUTHORITY_RESPONSE_DOMAIN,
        body,
    })
    .map_err(|_| PortError::invalid_data())
}
