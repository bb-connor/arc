use std::path::PathBuf;

use chio_core::capability::governance::{GovernedApprovalToken, GovernedTransactionIntent};
use chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS;
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, Hash, PublicKey, Signature, SigningAlgorithm};
use chio_kernel::threshold_approval::ThresholdApprovalProposal;
use chio_kernel::{
    active_response_admission_artifact_payload_digest,
    active_response_artifact_authority_signing_bytes, active_response_submission_proof_digest,
    ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
    ActiveResponseAuthorizationRequest, ActiveResponseSubmissionProof,
};
use chio_secure_ipc::{validate_unix_socket_path, PeerIdentity};
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
    ActiveResponseAuthorityHandler, ActiveResponseAuthorityHandlerError,
    ActiveResponseAuthorityHandlerResult, ActiveResponseAuthorityProtocolServer,
    ActiveResponseAuthorityProtocolServerConfig, ActiveResponseAuthorityServeOutcome,
};

pub const ACTIVE_RESPONSE_AUTHORITY_SCHEMA: &str = "chio.active-response-policy-authority.v2";
pub const ACTIVE_RESPONSE_AUTHORITY_REQUEST_DOMAIN: &str =
    "chio.active-response-policy-authority.request.v2\0";
pub const ACTIVE_RESPONSE_AUTHORITY_RESPONSE_DOMAIN: &str =
    "chio.active-response-policy-authority.response.v2\0";
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
    pub deployment_digest: Digest32,
    pub store_digest: Digest32,
    pub timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
}

impl ProductionActiveResponseAuthorityFileConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if validate_unix_socket_path(&self.socket_path).is_err()
            || self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > MAX_ACTIVE_RESPONSE_AUTHORITY_CLOCK_SKEW_SECONDS
            || self.expected_peer.process_id == 0
            || self.deployment_digest.is_zero()
            || self.store_digest.is_zero()
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
    pub deployment_digest: Digest32,
    pub store_digest: Digest32,
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
    Ready {
        protocol: String,
        #[serde(rename = "deploymentDigest")]
        deployment_digest: Digest32,
        #[serde(rename = "storeDigest")]
        store_digest: Digest32,
    },
    Policy(Box<ActiveResponsePolicySelectionWire>),
    Artifacts(Box<ActiveResponseAdmissionArtifactsWire>),
    Rejected(ActiveResponseAuthorityRejection),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAuthorityResponseBody {
    pub schema: String,
    pub deployment_digest: Digest32,
    pub store_digest: Digest32,
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

pub fn validate_active_response_policy_selection(
    evidence_id: &OpaqueReceiptRef,
    binding: &AttestedFindingBatchBinding,
    selection: &ActiveResponsePolicySelectionWire,
) -> PortResult<()> {
    if selection.action_id != binding.action_id
        || &selection.evidence_id != evidence_id
        || &binding.evidence_id != evidence_id
        || selection.affected_ids.as_slice().is_empty()
        || selection.effects.as_slice().is_empty()
        || selection.ttl_ms == 0
        || selection.created_at_unix_ms == 0
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub fn validate_active_response_artifacts_draft(
    response_plan: &ResponsePlan,
    expected_ref: &AdmissionArtifactRef,
    expected_authority: &PublicKey,
    draft: &ActiveResponseAdmissionArtifactsDraftWire,
) -> PortResult<()> {
    let proof = &draft.submission_proof;
    let body = &draft.authority_attestation_body;
    let plan_body_hash = canonical_hex_digest(&proof.body.plan_body_hash)?;
    let governed_intent_hash = canonical_hex_digest(&proof.body.governed_intent_hash)?;
    let expected_payload_digest = active_response_admission_artifact_payload_digest(
        &response_plan.authorization_body(),
        &draft.operator_capability,
        &draft.governed_intent,
        proof,
        &draft.threshold_proposal,
        draft.approval_tokens.as_slice(),
    )
    .map_err(|_| PortError::integrity_failure())?;
    let expected_proof_digest = active_response_submission_proof_digest(proof)
        .map_err(|_| PortError::integrity_failure())?;
    ActiveResponseAuthorizationRequest::new(
        draft.operator_capability.clone(),
        response_plan.authorization_body(),
        draft.governed_intent.clone(),
        proof.clone(),
    )
    .map_err(|_| PortError::integrity_failure())?;
    active_response_artifact_authority_signing_bytes(body)
        .map_err(|_| PortError::integrity_failure())?;
    if draft.action_id != response_plan.action_id
        || draft.plan_hash != response_plan.plan_hash
        || &draft.admission_artifact_ref != expected_ref
        || body.artifact_ref != *expected_ref
        || body.action_id != response_plan.action_id
        || body.tenant_id != response_plan.tenant_id
        || &body.authority != expected_authority
        || body.artifact_payload_digest != expected_payload_digest
        || body.submission_proof_digest != expected_proof_digest
        || body.plan_body_hash != plan_body_hash
        || body.plan_body_hash != response_plan.plan_hash
        || body.governed_intent_hash != governed_intent_hash
        || body.submitter != proof.body.submitter
        || proof.body.action_id != response_plan.action_id
        || proof.body.tenant_id != response_plan.tenant_id
        || proof.body.issued_at_unix_ms != body.issued_at_unix_ms
        || proof.body.expires_at_unix_ms != body.expires_at_unix_ms
        || body.issued_at_unix_ms < response_plan.created_at_unix_ms
        || body.issued_at_unix_ms >= response_plan.expires_at_unix_ms
        || body.expires_at_unix_ms > response_plan.expires_at_unix_ms
        || draft
            .governed_intent
            .binding_hash()
            .map_err(|_| PortError::integrity_failure())?
            != proof.body.governed_intent_hash
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn canonical_hex_digest(value: &str) -> PortResult<Digest32> {
    let parsed = Hash::from_hex(value).map_err(|_| PortError::integrity_failure())?;
    if parsed.to_hex() != value || parsed.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PortError::integrity_failure());
    }
    Ok(Digest32::new(*parsed.as_bytes()))
}
