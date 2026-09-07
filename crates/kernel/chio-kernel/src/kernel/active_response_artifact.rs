use chio_core::capability::governance::{GovernedApprovalToken, GovernedTransactionIntent};
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, sha256, Hash, PublicKey, Signature, SigningBackend};
use chio_security_types::ports::{ActionId, AdmissionArtifactRef, Digest32, TenantId};
use chio_security_types::ResponsePlanAuthorizationBody;
use serde::{Deserialize, Serialize};

use crate::threshold_approval::ThresholdApprovalProposal;

use super::active_response_admission::{
    ActiveResponseSubmissionProof, VerifiedActiveResponseBindings,
};
use super::active_response_coordinator::ActiveResponseAdmissionRequest;
use super::{ChioKernel, KernelError};

pub const ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_ATTESTATION_SCHEMA: &str =
    "chio.active-response-artifact-authority-attestation.v1";
pub const ACTIVE_RESPONSE_ADMISSION_ARTIFACT_PAYLOAD_SCHEMA: &str =
    "chio.attested-finding-admission-artifact-payload.v1";
const ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"chio.active-response-artifact-authority-attestation.v1\0";
const ACTIVE_RESPONSE_ADMISSION_ARTIFACT_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"chio.attested-finding-admission-artifact-payload.v1\0";
const ACTIVE_RESPONSE_SUBMISSION_PROOF_DIGEST_DOMAIN: &[u8] =
    b"chio.active-response-submission-proof-digest.v1\0";

/// Trusted authority binding for one exact active-response admission artifact.
///
/// The authority signs the durable artifact reference, typed plan identity,
/// canonical artifact payload, complete submitter proof, authenticated
/// submitter, plan and intent hashes, and the submitter-proof validity window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseArtifactAuthorityAttestationBody {
    pub schema: String,
    pub artifact_ref: AdmissionArtifactRef,
    pub action_id: ActionId,
    pub tenant_id: TenantId,
    pub artifact_payload_digest: Digest32,
    pub submission_proof_digest: Digest32,
    pub plan_body_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub submitter: PublicKey,
    pub authority: PublicKey,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Unsigned claims used to construct a validated artifact-authority attestation body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseArtifactAuthorityAttestationInput {
    pub artifact_ref: AdmissionArtifactRef,
    pub action_id: ActionId,
    pub tenant_id: TenantId,
    pub artifact_payload_digest: Digest32,
    pub submission_proof_digest: Digest32,
    pub plan_body_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub submitter: PublicKey,
    pub authority: PublicKey,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl ActiveResponseArtifactAuthorityAttestationBody {
    pub fn new(
        input: ActiveResponseArtifactAuthorityAttestationInput,
    ) -> Result<Self, ActiveResponseArtifactAuthorityAttestationError> {
        let ActiveResponseArtifactAuthorityAttestationInput {
            artifact_ref,
            action_id,
            tenant_id,
            artifact_payload_digest,
            submission_proof_digest,
            plan_body_hash,
            governed_intent_hash,
            submitter,
            authority,
            issued_at_unix_ms,
            expires_at_unix_ms,
        } = input;
        let body = Self {
            schema: ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_ATTESTATION_SCHEMA.to_string(),
            artifact_ref,
            action_id,
            tenant_id,
            artifact_payload_digest,
            submission_proof_digest,
            plan_body_hash,
            governed_intent_hash,
            submitter,
            authority,
            issued_at_unix_ms,
            expires_at_unix_ms,
        };
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), ActiveResponseArtifactAuthorityAttestationError> {
        if self.schema != ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_ATTESTATION_SCHEMA {
            return Err(ActiveResponseArtifactAuthorityAttestationError::Invalid(
                "authority attestation schema is unsupported".to_string(),
            ));
        }
        if digest_is_zero(&self.artifact_payload_digest)
            || digest_is_zero(&self.submission_proof_digest)
            || digest_is_zero(&self.plan_body_hash)
            || digest_is_zero(&self.governed_intent_hash)
        {
            return Err(ActiveResponseArtifactAuthorityAttestationError::Invalid(
                "authority attestation contains a zero digest".to_string(),
            ));
        }
        if self.authority == self.submitter {
            return Err(ActiveResponseArtifactAuthorityAttestationError::Invalid(
                "submission authority must be distinct from the submitter".to_string(),
            ));
        }
        if self.issued_at_unix_ms == 0 || self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ActiveResponseArtifactAuthorityAttestationError::Invalid(
                "authority attestation validity window is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseArtifactAuthorityAttestation {
    pub body: ActiveResponseArtifactAuthorityAttestationBody,
    pub signature: Signature,
}

impl ActiveResponseArtifactAuthorityAttestation {
    pub fn sign_with_backend(
        body: ActiveResponseArtifactAuthorityAttestationBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self, ActiveResponseArtifactAuthorityAttestationError> {
        body.validate()?;
        let expected_authority = body.authority.clone();
        let outcome = backend
            .sign_bytes_for_identity(
                &expected_authority,
                &active_response_artifact_authority_signing_bytes(&body)?,
            )
            .map_err(|error| {
                ActiveResponseArtifactAuthorityAttestationError::Signing(error.to_string())
            })?;
        let signing_bytes = active_response_artifact_authority_signing_bytes(&body)?;
        let expected_algorithm = expected_authority.algorithm();
        if outcome.public_key != expected_authority
            || outcome.algorithm != expected_algorithm
            || outcome.signature.algorithm() != expected_algorithm
            || !expected_authority.verify(&signing_bytes, &outcome.signature)
        {
            return Err(ActiveResponseArtifactAuthorityAttestationError::Signing(
                "backend returned an invalid authority identity or signature".to_string(),
            ));
        }
        Ok(Self {
            body,
            signature: outcome.signature,
        })
    }

    pub fn verify_signature(
        &self,
    ) -> Result<bool, ActiveResponseArtifactAuthorityAttestationError> {
        self.body.validate()?;
        if self.signature.algorithm() != self.body.authority.algorithm() {
            return Ok(false);
        }
        Ok(self.body.authority.verify(
            &active_response_artifact_authority_signing_bytes(&self.body)?,
            &self.signature,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ActiveResponseArtifactAuthorityAttestationError {
    #[error("active-response artifact authority attestation is invalid: {0}")]
    Invalid(String),
    #[error("active-response artifact authority attestation signing failed: {0}")]
    Signing(String),
}

pub fn active_response_artifact_authority_signing_bytes(
    body: &ActiveResponseArtifactAuthorityAttestationBody,
) -> Result<Vec<u8>, ActiveResponseArtifactAuthorityAttestationError> {
    body.validate()?;
    let canonical = canonical_json_bytes(body).map_err(|error| {
        ActiveResponseArtifactAuthorityAttestationError::Invalid(error.to_string())
    })?;
    let mut signing_bytes = Vec::with_capacity(
        ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_SIGNATURE_DOMAIN.len() + canonical.len(),
    );
    signing_bytes.extend_from_slice(ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_SIGNATURE_DOMAIN);
    signing_bytes.extend_from_slice(&canonical);
    Ok(signing_bytes)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalActiveResponseAdmissionArtifactPayload<'a> {
    schema: &'static str,
    plan_body: &'a ResponsePlanAuthorizationBody,
    operator_capability: &'a CapabilityToken,
    governed_intent: &'a GovernedTransactionIntent,
    submission_proof: &'a ActiveResponseSubmissionProof,
    threshold_proposal: &'a Option<ThresholdApprovalProposal>,
    approval_tokens: Vec<&'a GovernedApprovalToken>,
}

pub fn active_response_admission_artifact_payload_digest(
    plan_body: &ResponsePlanAuthorizationBody,
    operator_capability: &CapabilityToken,
    governed_intent: &GovernedTransactionIntent,
    submission_proof: &ActiveResponseSubmissionProof,
    threshold_proposal: &Option<ThresholdApprovalProposal>,
    approval_tokens: &[GovernedApprovalToken],
) -> Result<Digest32, ActiveResponseArtifactAuthorityAttestationError> {
    let mut ordered_tokens = approval_tokens
        .iter()
        .map(|token| {
            canonical_json_bytes(token)
                .map(|canonical| (canonical, token))
                .map_err(|error| {
                    ActiveResponseArtifactAuthorityAttestationError::Invalid(error.to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ordered_tokens.sort_by(|left, right| left.0.cmp(&right.0));
    let canonical = canonical_json_bytes(&CanonicalActiveResponseAdmissionArtifactPayload {
        schema: ACTIVE_RESPONSE_ADMISSION_ARTIFACT_PAYLOAD_SCHEMA,
        plan_body,
        operator_capability,
        governed_intent,
        submission_proof,
        threshold_proposal,
        approval_tokens: ordered_tokens.into_iter().map(|(_, token)| token).collect(),
    })
    .map_err(|error| ActiveResponseArtifactAuthorityAttestationError::Invalid(error.to_string()))?;
    Ok(domain_digest(
        ACTIVE_RESPONSE_ADMISSION_ARTIFACT_PAYLOAD_DIGEST_DOMAIN,
        &canonical,
    ))
}

pub fn active_response_submission_proof_digest(
    submission_proof: &ActiveResponseSubmissionProof,
) -> Result<Digest32, ActiveResponseArtifactAuthorityAttestationError> {
    let canonical = canonical_json_bytes(submission_proof).map_err(|error| {
        ActiveResponseArtifactAuthorityAttestationError::Invalid(error.to_string())
    })?;
    Ok(domain_digest(
        ACTIVE_RESPONSE_SUBMISSION_PROOF_DIGEST_DOMAIN,
        &canonical,
    ))
}

impl ChioKernel {
    pub fn set_active_response_submission_authority(
        &mut self,
        authority: PublicKey,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_active_response_deactivated_for_authority_change()?;
        validate_submission_authority_key(&authority)?;
        if self
            .active_response_submission_authority
            .as_ref()
            .is_some_and(|installed| installed != &authority)
        {
            return Err(KernelError::Internal(
                "active-response submission authority cannot change after installation".to_string(),
            ));
        }
        self.active_response_submission_authority = Some(authority);
        Ok(())
    }

    pub(super) fn ensure_active_response_submission_authority_configured(
        &self,
    ) -> Result<(), KernelError> {
        self.active_response_submission_authority
            .as_ref()
            .map(|_| ())
            .ok_or_else(|| {
                KernelError::Internal(
                    "active-response submission authority is not installed".to_string(),
                )
            })
    }

    pub fn ensure_active_response_submission_authority_matches(
        &self,
        expected: &PublicKey,
    ) -> Result<(), KernelError> {
        match self.active_response_submission_authority.as_ref() {
            Some(installed) if installed == expected => Ok(()),
            Some(_) => Err(KernelError::Internal(
                "active-response submission authority does not match production configuration"
                    .to_string(),
            )),
            None => Err(KernelError::Internal(
                "active-response submission authority is not installed".to_string(),
            )),
        }
    }

    pub(super) fn verify_active_response_artifact_authority_attestation(
        &self,
        request: &ActiveResponseAdmissionRequest,
        bindings: &VerifiedActiveResponseBindings,
        now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let expected_authority = self
            .active_response_submission_authority
            .as_ref()
            .ok_or_else(|| denied("active-response submission authority is not installed"))?;
        let proof = request.authorization().submission_proof();
        let attestation = request.artifact_authority_attestation();
        let body = &attestation.body;
        let expected_plan_hash = digest_from_hex(bindings.plan_body_hash(), "plan body")?;
        let expected_intent_hash =
            digest_from_hex(bindings.governed_intent_hash(), "governed intent")?;
        let expected_payload_digest = active_response_admission_artifact_payload_digest(
            request.authorization().plan_body(),
            request.authorization().operator_capability(),
            request.authorization().governed_intent(),
            proof,
            request.threshold_proposal_option(),
            request.approval_tokens(),
        )
        .map_err(|error| denied(&error.to_string()))?;
        let expected_proof_digest = active_response_submission_proof_digest(proof)
            .map_err(|error| denied(&error.to_string()))?;
        if &body.artifact_ref != request.admission_artifact_ref()
            || body.action_id != request.response_plan().action_id
            || body.tenant_id != request.response_plan().tenant_id
            || body.artifact_payload_digest != expected_payload_digest
            || body.submission_proof_digest != expected_proof_digest
            || body.plan_body_hash != expected_plan_hash
            || body.governed_intent_hash != expected_intent_hash
            || body.submitter != *bindings.authenticated_submitter()
            || &body.authority != expected_authority
            || body.issued_at_unix_ms != proof.body.issued_at_unix_ms
            || body.expires_at_unix_ms != proof.body.expires_at_unix_ms
            || now_unix_ms < body.issued_at_unix_ms
            || now_unix_ms >= body.expires_at_unix_ms
        {
            return Err(denied(
                "trusted submission-authority attestation does not exactly match the active-response admission artifact",
            ));
        }
        if !self
            .capability_crypto_floor
            .allowed_signing_algorithms()
            .contains(&attestation.signature.algorithm())
        {
            return Err(denied(
                "submission-authority attestation algorithm is below the kernel crypto floor",
            ));
        }
        if !attestation
            .verify_signature()
            .map_err(|error| denied(&error.to_string()))?
        {
            return Err(denied(
                "submission-authority attestation signature verification failed",
            ));
        }
        Ok(())
    }
}

fn digest_from_hex(value: &str, label: &str) -> Result<Digest32, KernelError> {
    let parsed = Hash::from_hex(value).map_err(|_| {
        denied(&format!(
            "active-response {label} hash is not a 32-byte hexadecimal digest"
        ))
    })?;
    if parsed.to_hex() != value || parsed.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(denied(&format!(
            "active-response {label} hash is zero or not canonical lowercase hexadecimal"
        )));
    }
    Ok(Digest32::new(*parsed.as_bytes()))
}

fn digest_is_zero(digest: &Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest32 {
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(canonical);
    Digest32::new(*sha256(&bytes).as_bytes())
}

fn validate_submission_authority_key(authority: &PublicKey) -> Result<(), KernelError> {
    let encoded = authority.to_hex();
    let reparsed = PublicKey::from_hex(&encoded).map_err(|error| {
        KernelError::Internal(format!(
            "active-response submission authority key is malformed: {error}"
        ))
    })?;
    if &reparsed != authority || public_key_material_is_zero(&encoded) {
        return Err(KernelError::Internal(
            "active-response submission authority key is malformed or a zero sentinel".to_string(),
        ));
    }
    Ok(())
}

fn public_key_material_is_zero(encoded: &str) -> bool {
    if let Some(hybrid) = encoded.strip_prefix("hybrid:") {
        let Some((without_alg_set, _)) = hybrid.rsplit_once(':') else {
            return true;
        };
        let Some((classical, pq)) = without_alg_set.rsplit_once(':') else {
            return true;
        };
        return pq.bytes().all(|byte| byte == b'0') || public_key_material_is_zero(classical);
    }
    let material = encoded
        .strip_prefix("p256:")
        .or_else(|| encoded.strip_prefix("p384:"))
        .unwrap_or(encoded);
    let coordinates = material.strip_prefix("04").unwrap_or(material);
    coordinates.bytes().all(|byte| byte == b'0')
}

fn denied(message: &str) -> KernelError {
    KernelError::GovernedTransactionDenied(format!("active response denied: {message}"))
}
