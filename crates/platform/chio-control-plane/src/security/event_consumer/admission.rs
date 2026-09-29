


use super::GovernedApprovalToken;
use super::GovernedTransactionIntent;
use super::CapabilityToken;
use super::canonical_json_bytes;
use super::sha256;
use super::Hash;
use super::PublicKey;









use super::authorization_capability_hash;
use super::ThresholdApprovalProposal;
use super::active_response_admission_artifact_payload_digest;
use super::active_response_submission_proof_digest;
use super::ActiveResponseAdmissionRequest;
use super::ActiveResponseArtifactAuthorityAttestation;
use super::ActiveResponseAuthorizationRequest;
#[cfg(test)]
use super::ActiveResponseExecutionEvidence;

#[cfg(test)]
use super::ActiveResponseExecutorAuthorityIdentity;


use super::ActiveResponseSubmissionProof;
#[cfg(test)]
use super::AuthoritativeCorrelatedFindingEvidence;
#[cfg(test)]
use super::ChioKernel;

#[cfg(test)]
use super::KernelError;

#[cfg(test)]
use super::PreparedActiveResponseAdmission;

use super::opaque_admission_artifact;







#[cfg(test)]
use super::Clock;





use super::AdmissionArtifactRef;
#[cfg(test)]
use super::ApprovalVerifierPort;







#[cfg(test)]
use super::AttestedFindingResponseCompletionOutcome;
#[cfg(test)]
use super::AttestedFindingResponseCompletionState;

#[cfg(test)]
use super::AttestedFindingResponseOutboxKey;

#[cfg(test)]
use super::AttestedFindingResponseOutboxStore;
#[cfg(test)]
use super::AttestedFindingResponseOutboxTransition;



#[cfg(test)]
use super::CanonicalBody;

use super::Digest32;


use super::GovernedApprovalRequest;

#[cfg(test)]
use super::GovernedApprovalReservationMutation;
#[cfg(test)]
use super::OpaqueReceiptRef;
use super::PortError;
#[cfg(test)]
use super::PortErrorKind;
use super::PortResult;
#[cfg(test)]
use super::PreparedActiveResponseDispatchBinding;


use super::RecordId;



#[cfg(test)]
use super::TenantId;










use super::OperatorCapabilityBinding;
use super::ResponseApprovalRequirement;
use super::ResponseEffectSpec;
use super::ResponsePlan;

#[cfg(test)]
use super::SqliteSecurityStateStore;

use super::Serialize;
#[cfg(test)]
use super::json;
#[cfg(test)]
use super::BTreeMap;

#[cfg(test)]
use super::Arc;
#[cfg(test)]
use super::Mutex;














#[cfg(test)]
use super::build_attested_finding_batch_publication;































use super::map_approval_coordinator_error;


















#[cfg(test)]
use super::ReservedAttestedFindingResponsePlan;


/// Policy-owned response fields for one authoritative finding.
///
/// Persistence identities and finding authority fields are absent by design.
/// The trusted durable planner supplies those fields after this selection is
/// returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedFindingResponsePolicySelection {
    pub execution: chio_security_types::ResponseExecutionBinding,
    pub affected_ids: Vec<RecordId>,
    pub effects: Vec<ResponseEffectSpec>,
    pub ttl_ms: u64,
    pub created_at_unix_ms: u64,
    pub operator_capability: OperatorCapabilityBinding,
    pub approval_requirement: ResponseApprovalRequirement,
    pub submitter: RecordId,
    pub reason_hash: Digest32,
    pub admission_artifact_ref: AdmissionArtifactRef,
}

pub(super) const ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_SCHEMA: &str =
    "chio.attested-finding-admission-artifacts.v1";
pub(super) const ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_DIGEST_DOMAIN: &[u8] =
    b"chio.attested-finding-admission-artifact-bundle-digest.v1\0";

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CanonicalAttestedFindingAdmissionArtifactBundle<'a> {
    schema: &'static str,
    artifact_ref: &'a AdmissionArtifactRef,
    authority_attestation: &'a ActiveResponseArtifactAuthorityAttestation,
    payload_digest: &'a Digest32,
}

/// Signed authorization material for one exact reserved response plan.
///
/// Policy code may select and retrieve these artifacts, but it cannot assert
/// that a response was admitted or executed. The production coordinator feeds
/// the artifacts and the trusted reserved plan into the kernel, which verifies
/// the operator capability for both automatic and governed plans and performs
/// approval replay reservation and dispatch commitment for governed plans.
#[derive(Clone, Debug)]
pub struct AttestedFindingAdmissionArtifacts {
    payload: AttestedFindingAdmissionArtifactPayload,
}

#[derive(Clone, Debug)]
pub(super) enum AttestedFindingAdmissionArtifactPayload {
    Kernel(Box<KernelAttestedFindingAdmissionArtifactPayload>),
    #[cfg(test)]
    Synthetic {
        digest: Digest32,
    },
}

#[derive(Clone, Debug)]
pub(super) struct KernelAttestedFindingAdmissionArtifactPayload {
    artifact_ref: AdmissionArtifactRef,
    operator_capability: CapabilityToken,
    governed_intent: GovernedTransactionIntent,
    submission_proof: ActiveResponseSubmissionProof,
    authority_attestation: ActiveResponseArtifactAuthorityAttestation,
    threshold_proposal: Option<ThresholdApprovalProposal>,
    approval_tokens: Vec<GovernedApprovalToken>,
}

impl AttestedFindingAdmissionArtifacts {
    #[must_use]
    pub fn new(
        artifact_ref: AdmissionArtifactRef,
        operator_capability: CapabilityToken,
        governed_intent: GovernedTransactionIntent,
        submission_proof: ActiveResponseSubmissionProof,
        authority_attestation: ActiveResponseArtifactAuthorityAttestation,
        threshold_proposal: Option<ThresholdApprovalProposal>,
        approval_tokens: Vec<GovernedApprovalToken>,
    ) -> Self {
        Self {
            payload: AttestedFindingAdmissionArtifactPayload::Kernel(Box::new(
                KernelAttestedFindingAdmissionArtifactPayload {
                    artifact_ref,
                    operator_capability,
                    governed_intent,
                    submission_proof,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                },
            )),
        }
    }

    pub fn canonical_digest(&self, response_plan: &ResponsePlan) -> PortResult<Digest32> {
        match &self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let payload = payload.as_ref();
                let payload_digest = active_response_admission_artifact_payload_digest(
                    &response_plan.authorization_body(),
                    &payload.operator_capability,
                    &payload.governed_intent,
                    &payload.submission_proof,
                    &payload.threshold_proposal,
                    &payload.approval_tokens,
                )
                .map_err(|_| PortError::integrity_failure())?;
                canonical_admission_artifact_bundle_digest(
                    &payload.artifact_ref,
                    &payload.authority_attestation,
                    &payload_digest,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { digest } => {
                if digest.is_zero() {
                    Err(PortError::integrity_failure())
                } else {
                    Ok(*digest)
                }
            }
        }
    }

    pub fn verify_authority_attestation(
        &self,
        expected_ref: &AdmissionArtifactRef,
        response_plan: &ResponsePlan,
        expected_authority: &PublicKey,
        admission_time_unix_ms: u64,
    ) -> PortResult<Digest32> {
        match &self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let payload = payload.as_ref();
                let payload_digest = active_response_admission_artifact_payload_digest(
                    &response_plan.authorization_body(),
                    &payload.operator_capability,
                    &payload.governed_intent,
                    &payload.submission_proof,
                    &payload.threshold_proposal,
                    &payload.approval_tokens,
                )
                .map_err(|_| PortError::integrity_failure())?;
                let proof_digest =
                    active_response_submission_proof_digest(&payload.submission_proof)
                        .map_err(|_| PortError::integrity_failure())?;
                let attestation = &payload.authority_attestation.body;
                let plan_body_hash = digest_from_canonical_hex(
                    payload.submission_proof.body.plan_body_hash.as_str(),
                )?;
                let governed_intent_hash = digest_from_canonical_hex(
                    payload.submission_proof.body.governed_intent_hash.as_str(),
                )?;
                let signature_valid = payload
                    .authority_attestation
                    .verify_signature()
                    .map_err(|_| PortError::integrity_failure())?;
                if &payload.artifact_ref != expected_ref
                    || &attestation.artifact_ref != expected_ref
                    || attestation.action_id != response_plan.action_id
                    || attestation.tenant_id != response_plan.tenant_id
                    || attestation.artifact_payload_digest != payload_digest
                    || attestation.submission_proof_digest != proof_digest
                    || attestation.plan_body_hash != plan_body_hash
                    || attestation.governed_intent_hash != governed_intent_hash
                    || attestation.submitter != payload.submission_proof.body.submitter
                    || &attestation.authority != expected_authority
                    || payload.submission_proof.body.action_id.as_str()
                        != response_plan.action_id.as_str()
                    || payload.submission_proof.body.tenant_id != response_plan.tenant_id
                    || !payload
                        .submission_proof
                        .verify_signature()
                        .map_err(|_| PortError::integrity_failure())?
                    || attestation.issued_at_unix_ms
                        != payload.submission_proof.body.issued_at_unix_ms
                    || attestation.expires_at_unix_ms
                        != payload.submission_proof.body.expires_at_unix_ms
                    || attestation.issued_at_unix_ms < response_plan.created_at_unix_ms
                    || attestation.issued_at_unix_ms >= response_plan.expires_at_unix_ms
                    || attestation.issued_at_unix_ms > admission_time_unix_ms
                    || admission_time_unix_ms >= attestation.expires_at_unix_ms
                    || attestation.expires_at_unix_ms > response_plan.expires_at_unix_ms
                    || payload_digest.is_zero()
                    || proof_digest.is_zero()
                    || !signature_valid
                {
                    return Err(PortError::integrity_failure());
                }
                canonical_admission_artifact_bundle_digest(
                    &payload.artifact_ref,
                    &payload.authority_attestation,
                    &payload_digest,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { digest } => {
                if digest.is_zero() {
                    Err(PortError::integrity_failure())
                } else {
                    Ok(*digest)
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn synthetic(digest: Digest32) -> Self {
        Self {
            payload: AttestedFindingAdmissionArtifactPayload::Synthetic { digest },
        }
    }
}

pub(super) fn governed_approval_request_from_native(
    request: &ActiveResponseAdmissionRequest,
) -> PortResult<GovernedApprovalRequest> {
    let response_plan = request.response_plan();
    let ResponseApprovalRequirement::Governed { policy_id } = &response_plan.approval_requirement
    else {
        return Err(PortError::integrity_failure());
    };
    let proposal = request
        .threshold_proposal()
        .ok_or_else(PortError::integrity_failure)?;
    let proposal_digest = digest_from_canonical_hex(
        &proposal
            .proposal_hash()
            .map_err(|_| PortError::integrity_failure())?,
    )?;
    let governed_intent_hash = digest_from_canonical_hex(
        &request
            .authorization()
            .governed_intent()
            .binding_hash()
            .map_err(|_| PortError::integrity_failure())?,
    )?;
    let operator_capability_digest = digest_from_canonical_hex(
        &authorization_capability_hash(request.authorization().operator_capability())
            .map_err(|_| PortError::integrity_failure())?,
    )?;
    let proposal_expires_at_unix_ms = proposal
        .body()
        .proposal_deadline
        .checked_mul(1_000)
        .ok_or_else(PortError::integrity_failure)?;
    let threshold_proposal = request.threshold_proposal().cloned();
    let payload_digest = active_response_admission_artifact_payload_digest(
        &response_plan.authorization_body(),
        request.authorization().operator_capability(),
        request.authorization().governed_intent(),
        request.authorization().submission_proof(),
        &threshold_proposal,
        request.approval_tokens(),
    )
    .map_err(|_| PortError::integrity_failure())?;
    let artifact_digest = canonical_admission_artifact_bundle_digest(
        request.admission_artifact_ref(),
        request.artifact_authority_attestation(),
        &payload_digest,
    )?;
    let admission_artifact =
        opaque_admission_artifact(request.admission_artifact_ref().clone(), artifact_digest)
            .map_err(map_approval_coordinator_error)?;
    Ok(GovernedApprovalRequest {
        tenant_id: response_plan.tenant_id.clone(),
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        policy_hash: response_plan.policy_hash,
        approval_policy_id: policy_id.clone(),
        operator_capability_digest,
        proposal_digest,
        proposal_expires_at_unix_ms,
        governed_intent_hash,
        plan_expires_at_unix_ms: response_plan.expires_at_unix_ms,
        admission_artifact,
    })
}

pub(super) fn canonical_admission_artifact_bundle_digest(
    artifact_ref: &AdmissionArtifactRef,
    authority_attestation: &ActiveResponseArtifactAuthorityAttestation,
    payload_digest: &Digest32,
) -> PortResult<Digest32> {
    if payload_digest.is_zero() {
        return Err(PortError::integrity_failure());
    }
    let body = CanonicalAttestedFindingAdmissionArtifactBundle {
        schema: ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_SCHEMA,
        artifact_ref,
        authority_attestation,
        payload_digest,
    };
    let canonical = canonical_json_bytes(&body).map_err(|_| PortError::integrity_failure())?;
    Ok(domain_separated_artifact_digest(
        ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_DIGEST_DOMAIN,
        &canonical,
    ))
}

pub(super) fn digest_from_canonical_hex(value: &str) -> PortResult<Digest32> {
    let parsed = Hash::from_hex(value).map_err(|_| PortError::integrity_failure())?;
    if parsed.to_hex() != value || parsed.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PortError::integrity_failure());
    }
    Ok(Digest32::new(*parsed.as_bytes()))
}

pub(super) fn domain_separated_artifact_digest(domain: &[u8], canonical: &[u8]) -> Digest32 {
    let mut material = Vec::with_capacity(domain.len().saturating_add(canonical.len()));
    material.extend_from_slice(domain);
    material.extend_from_slice(canonical);
    Digest32::new(*sha256(&material).as_bytes())
}

#[path = "admission_request.rs"]
mod admission_request;

#[cfg(test)]
#[path = "tests/real_adapter.rs"]
mod real_adapter_tests;
