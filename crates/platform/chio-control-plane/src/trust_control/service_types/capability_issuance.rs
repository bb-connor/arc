#[cfg(test)]
use chio_core::SigningBackend;
use chio_core::{
    canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm,
};
use chio_security_types::ports::{LineageId, TenantId};
use serde::{Deserialize, Serialize};

use super::super::*;

pub(crate) const CAPABILITY_ISSUANCE_REQUEST_SCHEMA: &str = "chio.capability-issuance-request.v2";
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_SCHEMA: &str = "chio.capability-issuance-response.v1";
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA: &str =
    "chio.capability-issuance-response-envelope.v2";
const CAPABILITY_ISSUANCE_REQUEST_DIGEST_DOMAIN: &str = "chio.capability-issuance-request.v2\0";
const CAPABILITY_ISSUANCE_WORKLOAD_PROOF_DOMAIN: &str =
    "chio.capability-issuance-workload-proof.v1\0";
const CAPABILITY_ISSUANCE_RESPONSE_SIGNATURE_DOMAIN: &str =
    "chio.capability-issuance-response-envelope.v2\0";
const CAPABILITY_SESSION_ADMISSION_SCHEMA: &str = "chio.capability-session-admission.v1";
const CAPABILITY_SESSION_ADMISSION_SIGNATURE_DOMAIN: &str =
    "chio.capability-session-admission.v1\0";
const CAPABILITY_SESSION_ADMISSION_NONCE_DOMAIN: &str =
    "chio.capability-session-admission-nonce.v1\0";
pub(crate) const CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS: u64 = 60;
const CAPABILITY_SESSION_ADMISSION_TTL_SECS: u64 = 5 * 60;
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CapabilitySessionAdmissionBody {
    pub(crate) schema: String,
    pub(crate) admission_nonce: String,
    pub(crate) request_nonce: String,
    pub(crate) request_scope_sha256: String,
    pub(crate) request_ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_attestation_sha256: Option<String>,
    pub(crate) expected_authority_public_key: PublicKey,
    pub(crate) expected_authority_generation: u64,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) tenant_id: TenantId,
    pub(crate) lineage_id: LineageId,
    pub(crate) security_session_id: String,
    pub(crate) principal_id: String,
    pub(crate) isolation_epoch_id: String,
    pub(crate) context_generation: u64,
    pub(crate) workload_id: String,
    pub(crate) server_id: String,
    pub(crate) subject_public_key: PublicKey,
    pub(crate) workload_signer_public_key: PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedCapabilitySessionAdmission {
    pub(crate) schema: String,
    pub(crate) body: CapabilitySessionAdmissionBody,
    pub(crate) signer_public_key: PublicKey,
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitySessionAdmissionNonceInput<'a> {
    schema: &'a str,
    request_nonce: &'a str,
    request_scope_sha256: &'a str,
    request_ttl_seconds: u64,
    runtime_attestation_sha256: &'a Option<String>,
    expected_authority_public_key: &'a PublicKey,
    expected_authority_generation: u64,
    issued_at: u64,
    tenant_id: &'a TenantId,
    lineage_id: &'a LineageId,
    security_session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    context_generation: u64,
    workload_id: &'a str,
    server_id: &'a str,
    subject_public_key: &'a PublicKey,
    workload_signer_public_key: &'a PublicKey,
    admission_signer_public_key: &'a PublicKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitySessionAdmissionSigningPayload<'a> {
    schema: &'a str,
    body: &'a CapabilitySessionAdmissionBody,
    signer_public_key: &'a PublicKey,
    algorithm: SigningAlgorithm,
}

struct CapabilitySessionAdmissionInput<'a> {
    requested_at: u64,
    request_nonce: String,
    request_scope: &'a ChioScope,
    request_ttl_seconds: u64,
    runtime_attestation: Option<&'a RuntimeAttestationEvidence>,
    expected_authority_public_key: PublicKey,
    expected_authority_generation: u64,
    tenant_id: TenantId,
    lineage_id: LineageId,
    security_session_id: String,
    principal_id: String,
    isolation_epoch_id: String,
    context_generation: u64,
    workload_id: String,
    server_id: String,
    subject_public_key: PublicKey,
    workload_signer_public_key: PublicKey,
}

impl SignedCapabilitySessionAdmission {
    fn sign(
        input: CapabilitySessionAdmissionInput<'_>,
        admission_signer: &Keypair,
    ) -> Result<Self, String> {
        let CapabilitySessionAdmissionInput {
            requested_at,
            request_nonce,
            request_scope,
            request_ttl_seconds,
            runtime_attestation,
            expected_authority_public_key,
            expected_authority_generation,
            tenant_id,
            lineage_id,
            security_session_id,
            principal_id,
            isolation_epoch_id,
            context_generation,
            workload_id,
            server_id,
            subject_public_key,
            workload_signer_public_key,
        } = input;
        let signer_public_key = admission_signer.public_key();
        let request_scope_sha256 =
            sha256_hex(&canonical_json_bytes(request_scope).map_err(|error| error.to_string())?);
        let runtime_attestation_sha256 = runtime_attestation
            .map(canonical_json_bytes)
            .transpose()
            .map_err(|error| error.to_string())?
            .map(|bytes| sha256_hex(&bytes));
        let nonce_input = CapabilitySessionAdmissionNonceInput {
            schema: CAPABILITY_SESSION_ADMISSION_SCHEMA,
            request_nonce: &request_nonce,
            request_scope_sha256: &request_scope_sha256,
            request_ttl_seconds,
            runtime_attestation_sha256: &runtime_attestation_sha256,
            expected_authority_public_key: &expected_authority_public_key,
            expected_authority_generation,
            issued_at: requested_at,
            tenant_id: &tenant_id,
            lineage_id: &lineage_id,
            security_session_id: &security_session_id,
            principal_id: &principal_id,
            isolation_epoch_id: &isolation_epoch_id,
            context_generation,
            workload_id: &workload_id,
            server_id: &server_id,
            subject_public_key: &subject_public_key,
            workload_signer_public_key: &workload_signer_public_key,
            admission_signer_public_key: &signer_public_key,
        };
        let nonce_canonical =
            canonical_json_bytes(&nonce_input).map_err(|error| error.to_string())?;
        let mut nonce_preimage = Vec::with_capacity(
            CAPABILITY_SESSION_ADMISSION_NONCE_DOMAIN.len() + nonce_canonical.len(),
        );
        nonce_preimage.extend_from_slice(CAPABILITY_SESSION_ADMISSION_NONCE_DOMAIN.as_bytes());
        nonce_preimage.extend_from_slice(&nonce_canonical);
        let expires_at = requested_at
            .checked_add(CAPABILITY_SESSION_ADMISSION_TTL_SECS)
            .ok_or_else(|| "capability session admission expiry overflows".to_string())?;
        let body = CapabilitySessionAdmissionBody {
            schema: CAPABILITY_SESSION_ADMISSION_SCHEMA.to_string(),
            admission_nonce: sha256_hex(&nonce_preimage),
            request_nonce,
            request_scope_sha256,
            request_ttl_seconds,
            runtime_attestation_sha256,
            expected_authority_public_key,
            expected_authority_generation,
            issued_at: requested_at,
            expires_at,
            tenant_id,
            lineage_id,
            security_session_id,
            principal_id,
            isolation_epoch_id,
            context_generation,
            workload_id,
            server_id,
            subject_public_key,
            workload_signer_public_key,
        };
        let algorithm = signer_public_key.algorithm();
        let signing_bytes =
            capability_session_admission_signing_bytes(&body, &signer_public_key, algorithm)?;
        Ok(Self {
            schema: CAPABILITY_SESSION_ADMISSION_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: admission_signer.sign(&signing_bytes),
        })
    }

    pub(crate) fn verify_for_request(
        &self,
        request: &IssueCapabilityRequest,
        expected_signer: &PublicKey,
        validation_time: u64,
    ) -> Result<(), String> {
        if self.schema != CAPABILITY_SESSION_ADMISSION_SCHEMA
            || self.body.schema != CAPABILITY_SESSION_ADMISSION_SCHEMA
        {
            return Err("capability session admission schema mismatch".to_string());
        }
        validate_lower_hex_digest(
            &self.body.admission_nonce,
            "capability session admission nonce",
        )?;
        if &self.signer_public_key != expected_signer
            || self.algorithm != expected_signer.algorithm()
            || self.signature.algorithm() != self.algorithm
        {
            return Err("capability session admission signer is not pinned".to_string());
        }
        if self.body.issued_at
            > validation_time.saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
            || self.body.expires_at <= validation_time
            || self.body.expires_at
                != self
                    .body
                    .issued_at
                    .checked_add(CAPABILITY_SESSION_ADMISSION_TTL_SECS)
                    .ok_or_else(|| "capability session admission lifetime overflows".to_string())?
        {
            return Err("capability session admission is outside its validity window".to_string());
        }
        let request_scope_sha256 =
            sha256_hex(&canonical_json_bytes(&request.scope).map_err(|error| error.to_string())?);
        let runtime_attestation_sha256 = request
            .runtime_attestation
            .as_ref()
            .map(canonical_json_bytes)
            .transpose()
            .map_err(|error| error.to_string())?
            .map(|bytes| sha256_hex(&bytes));
        if self.body.request_nonce != request.request_nonce
            || self.body.request_scope_sha256 != request_scope_sha256
            || self.body.request_ttl_seconds != request.ttl_seconds
            || self.body.runtime_attestation_sha256 != runtime_attestation_sha256
            || self.body.expected_authority_public_key != request.expected_authority_public_key
            || self.body.expected_authority_generation != request.expected_authority_generation
            || self.body.issued_at != request.requested_at
            || self.body.tenant_id != request.tenant_id
            || self.body.lineage_id != request.lineage_id
            || self.body.security_session_id != request.security_session_id
            || self.body.principal_id != request.principal_id
            || self.body.isolation_epoch_id != request.isolation_epoch_id
            || self.body.context_generation != request.context_generation
            || self.body.workload_id != request.workload_id
            || self.body.server_id != request.server_id
            || self.body.subject_public_key.to_hex() != request.subject_public_key
            || self.body.workload_signer_public_key != request.workload_signer_public_key
        {
            return Err("capability session admission does not bind the exact request".to_string());
        }
        let nonce_input = CapabilitySessionAdmissionNonceInput {
            schema: CAPABILITY_SESSION_ADMISSION_SCHEMA,
            request_nonce: &self.body.request_nonce,
            request_scope_sha256: &self.body.request_scope_sha256,
            request_ttl_seconds: self.body.request_ttl_seconds,
            runtime_attestation_sha256: &self.body.runtime_attestation_sha256,
            expected_authority_public_key: &self.body.expected_authority_public_key,
            expected_authority_generation: self.body.expected_authority_generation,
            issued_at: self.body.issued_at,
            tenant_id: &self.body.tenant_id,
            lineage_id: &self.body.lineage_id,
            security_session_id: &self.body.security_session_id,
            principal_id: &self.body.principal_id,
            isolation_epoch_id: &self.body.isolation_epoch_id,
            context_generation: self.body.context_generation,
            workload_id: &self.body.workload_id,
            server_id: &self.body.server_id,
            subject_public_key: &self.body.subject_public_key,
            workload_signer_public_key: &self.body.workload_signer_public_key,
            admission_signer_public_key: &self.signer_public_key,
        };
        let canonical = canonical_json_bytes(&nonce_input).map_err(|error| error.to_string())?;
        let mut nonce_preimage =
            Vec::with_capacity(CAPABILITY_SESSION_ADMISSION_NONCE_DOMAIN.len() + canonical.len());
        nonce_preimage.extend_from_slice(CAPABILITY_SESSION_ADMISSION_NONCE_DOMAIN.as_bytes());
        nonce_preimage.extend_from_slice(&canonical);
        if self.body.admission_nonce != sha256_hex(&nonce_preimage) {
            return Err("capability session admission nonce is not deterministic".to_string());
        }
        let signing_bytes = capability_session_admission_signing_bytes(
            &self.body,
            &self.signer_public_key,
            self.algorithm,
        )?;
        if !self
            .signer_public_key
            .verify(&signing_bytes, &self.signature)
        {
            return Err("capability session admission signature is invalid".to_string());
        }
        Ok(())
    }

    pub(crate) fn binding_digest(&self) -> Result<String, String> {
        let canonical = canonical_json_bytes(self).map_err(|error| error.to_string())?;
        Ok(sha256_hex(&canonical))
    }
}

fn capability_session_admission_signing_bytes(
    body: &CapabilitySessionAdmissionBody,
    signer_public_key: &PublicKey,
    algorithm: SigningAlgorithm,
) -> Result<Vec<u8>, String> {
    let payload = CapabilitySessionAdmissionSigningPayload {
        schema: CAPABILITY_SESSION_ADMISSION_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
    let mut bytes =
        Vec::with_capacity(CAPABILITY_SESSION_ADMISSION_SIGNATURE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(CAPABILITY_SESSION_ADMISSION_SIGNATURE_DOMAIN.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssueCapabilityRequest {
    pub(crate) schema: String,
    pub(crate) request_nonce: String,
    pub(crate) requested_at: u64,
    pub(crate) tenant_id: TenantId,
    pub(crate) lineage_id: LineageId,
    pub(crate) security_session_id: String,
    pub(crate) principal_id: String,
    pub(crate) isolation_epoch_id: String,
    pub(crate) context_generation: u64,
    pub(crate) workload_id: String,
    pub(crate) server_id: String,
    pub(crate) expected_authority_public_key: PublicKey,
    pub(crate) expected_authority_generation: u64,
    pub(crate) subject_public_key: String,
    pub(crate) scope: ChioScope,
    pub(crate) ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_attestation: Option<RuntimeAttestationEvidence>,
    pub(crate) workload_signer_public_key: PublicKey,
    pub(crate) session_admission: SignedCapabilitySessionAdmission,
    pub(crate) workload_signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityIssuanceWorkloadProof<'a> {
    schema: &'a str,
    endpoint: &'a str,
    request_nonce: &'a str,
    requested_at: u64,
    tenant_id: &'a TenantId,
    lineage_id: &'a LineageId,
    security_session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    context_generation: u64,
    workload_id: &'a str,
    server_id: &'a str,
    expected_authority_public_key: &'a PublicKey,
    expected_authority_generation: u64,
    subject_public_key: &'a str,
    scope: &'a ChioScope,
    ttl_seconds: u64,
    runtime_attestation: &'a Option<RuntimeAttestationEvidence>,
    workload_signer_public_key: &'a PublicKey,
    session_admission: &'a SignedCapabilitySessionAdmission,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityIssuanceOperation<'a> {
    schema: &'a str,
    endpoint: &'a str,
    request_nonce: &'a str,
    tenant_id: &'a TenantId,
    lineage_id: &'a LineageId,
    security_session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    context_generation: u64,
    workload_id: &'a str,
    server_id: &'a str,
    expected_authority_public_key: &'a PublicKey,
    expected_authority_generation: u64,
    subject_public_key: &'a str,
    scope: &'a ChioScope,
    ttl_seconds: u64,
    runtime_attestation: &'a Option<RuntimeAttestationEvidence>,
    workload_signer_public_key: &'a PublicKey,
    session_admission: &'a SignedCapabilitySessionAdmission,
}

impl IssueCapabilityRequest {
    pub(crate) fn new(
        request_nonce: String,
        requested_at: u64,
        tenant_id: TenantId,
        lineage_id: LineageId,
        security_session_id: String,
        principal_id: String,
        isolation_epoch_id: String,
        context_generation: u64,
        workload_id: String,
        server_id: String,
        expected_authority_public_key: PublicKey,
        expected_authority_generation: u64,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
        workload_signer: &Keypair,
        session_admission_signer: &Keypair,
    ) -> Result<Self, String> {
        let workload_signer_public_key = workload_signer.public_key();
        let session_admission = SignedCapabilitySessionAdmission::sign(
            CapabilitySessionAdmissionInput {
                requested_at,
                request_nonce: request_nonce.clone(),
                request_scope: &scope,
                request_ttl_seconds: ttl_seconds,
                runtime_attestation: runtime_attestation.as_ref(),
                expected_authority_public_key: expected_authority_public_key.clone(),
                expected_authority_generation,
                tenant_id: tenant_id.clone(),
                lineage_id: lineage_id.clone(),
                security_session_id: security_session_id.clone(),
                principal_id: principal_id.clone(),
                isolation_epoch_id: isolation_epoch_id.clone(),
                context_generation,
                workload_id: workload_id.clone(),
                server_id: server_id.clone(),
                subject_public_key: subject.clone(),
                workload_signer_public_key: workload_signer_public_key.clone(),
            },
            session_admission_signer,
        )?;
        let mut request = Self {
            schema: CAPABILITY_ISSUANCE_REQUEST_SCHEMA.to_string(),
            request_nonce,
            requested_at,
            tenant_id,
            lineage_id,
            security_session_id,
            principal_id,
            isolation_epoch_id,
            context_generation,
            workload_id,
            server_id,
            expected_authority_public_key,
            expected_authority_generation,
            subject_public_key: subject.to_hex(),
            scope,
            ttl_seconds,
            runtime_attestation,
            workload_signer_public_key,
            session_admission,
            workload_signature: workload_signer.sign(b"uninitialized workload proof"),
        };
        let proof = request.workload_proof_bytes()?;
        request.workload_signature = workload_signer.sign(&proof);
        Ok(request)
    }

    pub(crate) fn validate_at(&self, now: u64) -> Result<(), String> {
        self.validate_structure_and_signature()?;
        self.validate_freshness_at(now)
    }

    pub(crate) fn validate_structure_and_signature(&self) -> Result<(), String> {
        if self.schema != CAPABILITY_ISSUANCE_REQUEST_SCHEMA {
            return Err("capability issuance request schema mismatch".to_string());
        }
        validate_capability_issuance_nonce(&self.request_nonce)?;
        PublicKey::from_hex(&self.subject_public_key)
            .map_err(|_| "capability issuance subject public key is invalid".to_string())?;
        for (label, value) in [
            ("security session", self.security_session_id.as_str()),
            ("principal", self.principal_id.as_str()),
            ("isolation epoch", self.isolation_epoch_id.as_str()),
            ("workload", self.workload_id.as_str()),
            ("server", self.server_id.as_str()),
        ] {
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                return Err(format!("capability issuance {label} binding is invalid"));
            }
        }
        if self.context_generation == 0 {
            return Err("capability issuance context generation is zero".to_string());
        }
        if self.expected_authority_generation == 0 {
            return Err("capability issuance expected authority generation is zero".to_string());
        }
        if self.workload_signature.algorithm() != self.workload_signer_public_key.algorithm()
            || !self
                .workload_signer_public_key
                .verify(&self.workload_proof_bytes()?, &self.workload_signature)
        {
            return Err("capability issuance workload proof is invalid".to_string());
        }
        self.session_admission.verify_for_request(
            self,
            &self.session_admission.signer_public_key,
            self.requested_at,
        )?;
        if self.ttl_seconds == 0 {
            return Err("capability issuance TTL must be greater than zero".to_string());
        }
        if self.requested_at.checked_add(self.ttl_seconds).is_none() {
            return Err("capability issuance TTL overflows the Unix timestamp range".to_string());
        }
        if let Some(evidence) = self.runtime_attestation.as_ref() {
            evidence
                .validate_workload_identity_binding()
                .map_err(|error| {
                    format!("capability issuance runtime attestation is invalid: {error}")
                })?;
            if !evidence.is_valid_at(self.requested_at) {
                return Err(
                    "capability issuance runtime attestation is not valid at request time"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    pub(crate) fn validate_freshness_at(&self, now: u64) -> Result<(), String> {
        if self.requested_at > now.saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
            || self.requested_at < now.saturating_sub(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        {
            return Err("capability issuance request is outside the freshness window".to_string());
        }
        Ok(())
    }

    pub(crate) fn binding_digest(&self) -> Result<String, String> {
        let operation = CapabilityIssuanceOperation {
            schema: &self.schema,
            endpoint: ISSUE_CAPABILITY_PATH,
            request_nonce: &self.request_nonce,
            tenant_id: &self.tenant_id,
            lineage_id: &self.lineage_id,
            security_session_id: &self.security_session_id,
            principal_id: &self.principal_id,
            isolation_epoch_id: &self.isolation_epoch_id,
            context_generation: self.context_generation,
            workload_id: &self.workload_id,
            server_id: &self.server_id,
            expected_authority_public_key: &self.expected_authority_public_key,
            expected_authority_generation: self.expected_authority_generation,
            subject_public_key: &self.subject_public_key,
            scope: &self.scope,
            ttl_seconds: self.ttl_seconds,
            runtime_attestation: &self.runtime_attestation,
            workload_signer_public_key: &self.workload_signer_public_key,
            session_admission: &self.session_admission,
        };
        let canonical = canonical_json_bytes(&operation).map_err(|error| error.to_string())?;
        let mut preimage =
            Vec::with_capacity(CAPABILITY_ISSUANCE_REQUEST_DIGEST_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(CAPABILITY_ISSUANCE_REQUEST_DIGEST_DOMAIN.as_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(sha256_hex(&preimage))
    }

    fn workload_proof_bytes(&self) -> Result<Vec<u8>, String> {
        let proof = CapabilityIssuanceWorkloadProof {
            schema: &self.schema,
            endpoint: ISSUE_CAPABILITY_PATH,
            request_nonce: &self.request_nonce,
            requested_at: self.requested_at,
            tenant_id: &self.tenant_id,
            lineage_id: &self.lineage_id,
            security_session_id: &self.security_session_id,
            principal_id: &self.principal_id,
            isolation_epoch_id: &self.isolation_epoch_id,
            context_generation: self.context_generation,
            workload_id: &self.workload_id,
            server_id: &self.server_id,
            expected_authority_public_key: &self.expected_authority_public_key,
            expected_authority_generation: self.expected_authority_generation,
            subject_public_key: &self.subject_public_key,
            scope: &self.scope,
            ttl_seconds: self.ttl_seconds,
            runtime_attestation: &self.runtime_attestation,
            workload_signer_public_key: &self.workload_signer_public_key,
            session_admission: &self.session_admission,
        };
        let canonical = canonical_json_bytes(&proof).map_err(|error| error.to_string())?;
        let mut bytes =
            Vec::with_capacity(CAPABILITY_ISSUANCE_WORKLOAD_PROOF_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(CAPABILITY_ISSUANCE_WORKLOAD_PROOF_DOMAIN.as_bytes());
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CapabilityIssuanceResponseBody {
    pub(crate) schema: String,
    pub(crate) endpoint: String,
    pub(crate) request_nonce: String,
    pub(crate) request_digest: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) authority_generation: u64,
    pub(crate) authority_rotated_at: u64,
    pub(crate) capability: CapabilityToken,
}

impl CapabilityIssuanceResponseBody {
    fn validate(&self) -> Result<(), String> {
        if self.schema != CAPABILITY_ISSUANCE_RESPONSE_SCHEMA {
            return Err("capability issuance response schema mismatch".to_string());
        }
        if self.endpoint != ISSUE_CAPABILITY_PATH {
            return Err("capability issuance response endpoint mismatch".to_string());
        }
        validate_capability_issuance_nonce(&self.request_nonce)?;
        validate_lower_hex_digest(&self.request_digest, "capability issuance request digest")?;
        if self.expires_at != self.capability.expires_at
            || self.capability.issued_at > self.issued_at
            || self.expires_at <= self.issued_at
        {
            return Err(
                "capability issuance response lifetime must match the issued capability"
                    .to_string(),
            );
        }
        if self.authority_generation == 0 {
            return Err("capability issuance authority generation is zero".to_string());
        }
        if self.authority_rotated_at > self.issued_at {
            return Err("capability issuance authority rotation time is in the future".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedIssueCapabilityResponse {
    pub(crate) schema: String,
    pub(crate) body: CapabilityIssuanceResponseBody,
    pub(crate) signer_public_key: PublicKey,
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) keyring_artifact_signature: Option<chio_keyring::KeyringArtifactSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_time_anchor: Option<chio_keyring::SignedArtifactTimeAnchor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityIssuanceResponseSigningPayload<'a> {
    schema: &'a str,
    body: &'a CapabilityIssuanceResponseBody,
    signer_public_key: &'a PublicKey,
    algorithm: SigningAlgorithm,
}

impl SignedIssueCapabilityResponse {
    #[cfg(test)]
    pub(crate) fn sign(
        request: &IssueCapabilityRequest,
        capability: CapabilityToken,
        keypair: &Keypair,
        authority_generation: u64,
        authority_rotated_at: u64,
        issued_at: u64,
    ) -> Result<Self, String> {
        request.validate_at(issued_at)?;
        let signer_public_key = keypair.public_key();
        if capability.issuer != signer_public_key {
            return Err(
                "capability issuance response signer does not match the capability issuer"
                    .to_string(),
            );
        }
        let expires_at = capability.expires_at;
        let body = CapabilityIssuanceResponseBody {
            schema: CAPABILITY_ISSUANCE_RESPONSE_SCHEMA.to_string(),
            endpoint: ISSUE_CAPABILITY_PATH.to_string(),
            request_nonce: request.request_nonce.clone(),
            request_digest: request.binding_digest()?,
            issued_at,
            expires_at,
            authority_generation,
            authority_rotated_at,
            capability,
        };
        body.validate()?;
        let algorithm = signer_public_key.algorithm();
        let signing_bytes =
            capability_issuance_response_signing_bytes(&body, &signer_public_key, algorithm)?;
        Ok(Self {
            schema: CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: keypair.sign(&signing_bytes),
            keyring_artifact_signature: None,
            artifact_time_anchor: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn sign_with_backend(
        request: &IssueCapabilityRequest,
        capability: CapabilityToken,
        backend: &dyn SigningBackend,
        authority_generation: u64,
        authority_rotated_at: u64,
        issued_at: u64,
    ) -> Result<Self, String> {
        let signer_public_key = request.expected_authority_public_key.clone();
        if capability.issuer != signer_public_key
            || backend.public_key() != signer_public_key
            || authority_generation != request.expected_authority_generation
        {
            return Err(
                "capability issuance backend does not match the pinned request epoch".to_string(),
            );
        }
        let body = CapabilityIssuanceResponseBody {
            schema: CAPABILITY_ISSUANCE_RESPONSE_SCHEMA.to_string(),
            endpoint: ISSUE_CAPABILITY_PATH.to_string(),
            request_nonce: request.request_nonce.clone(),
            request_digest: request.binding_digest()?,
            issued_at,
            expires_at: capability.expires_at,
            authority_generation,
            authority_rotated_at,
            capability,
        };
        body.validate()?;
        let algorithm = signer_public_key.algorithm();
        let signing_bytes =
            capability_issuance_response_signing_bytes(&body, &signer_public_key, algorithm)?;
        let outcome = backend
            .sign_bytes_for_identity(&signer_public_key, &signing_bytes)
            .map_err(|error| error.to_string())?;
        if outcome.public_key != signer_public_key
            || outcome.algorithm != algorithm
            || outcome.signature.algorithm() != algorithm
            || !signer_public_key.verify(&signing_bytes, &outcome.signature)
        {
            return Err(
                "capability issuance backend returned a mismatched response signature".to_string(),
            );
        }
        Ok(Self {
            schema: CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: outcome.signature,
            keyring_artifact_signature: None,
            artifact_time_anchor: None,
        })
    }

    pub(crate) fn sign_with_keyring_evidence(
        request: &IssueCapabilityRequest,
        capability: CapabilityToken,
        composition: &crate::KeyringRuntimeComposition,
        authority_generation: u64,
        authority_rotated_at: u64,
        issued_at: u64,
    ) -> Result<Self, String> {
        let signer_public_key = request.expected_authority_public_key.clone();
        if capability.issuer != signer_public_key
            || authority_generation != request.expected_authority_generation
        {
            return Err(
                "capability issuance keyring does not match the pinned request epoch".to_string(),
            );
        }
        let body = CapabilityIssuanceResponseBody {
            schema: CAPABILITY_ISSUANCE_RESPONSE_SCHEMA.to_string(),
            endpoint: ISSUE_CAPABILITY_PATH.to_string(),
            request_nonce: request.request_nonce.clone(),
            request_digest: request.binding_digest()?,
            issued_at,
            expires_at: capability.expires_at,
            authority_generation,
            authority_rotated_at,
            capability,
        };
        body.validate()?;
        let algorithm = signer_public_key.algorithm();
        let signing_bytes =
            capability_issuance_response_signing_bytes(&body, &signer_public_key, algorithm)?;
        let result = composition
            .sign_authority_artifact_with_evidence(&signer_public_key, &signing_bytes)
            .map_err(|error| error.to_string())?;
        if result.public_key != signer_public_key
            || result.algorithm != algorithm
            || result.signature.algorithm() != algorithm
            || result.evidence.artifact_signature != result.signature
            || result.signing_epoch.checked_add(1) != Some(authority_generation)
            || !signer_public_key.verify(&signing_bytes, &result.signature)
        {
            return Err(
                "capability issuance keyring returned mismatched artifact evidence".to_string(),
            );
        }
        let artifact_time_anchor = result.time_anchor.ok_or_else(|| {
            "capability issuance keyring omitted trusted-time evidence".to_string()
        })?;
        Ok(Self {
            schema: CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: result.signature,
            keyring_artifact_signature: Some(result.evidence),
            artifact_time_anchor: Some(artifact_time_anchor),
        })
    }

    pub(crate) fn verify(
        &self,
        expected_signer: &PublicKey,
        expected_generation: u64,
        expected_request: &IssueCapabilityRequest,
        now: u64,
    ) -> Result<(), String> {
        if self.schema != CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA {
            return Err("capability issuance response envelope schema mismatch".to_string());
        }
        self.body.validate()?;
        if &self.signer_public_key != expected_signer {
            return Err("capability issuance response signer is not pinned".to_string());
        }
        if self.body.authority_generation != expected_generation {
            return Err("capability issuance response generation is not pinned".to_string());
        }
        if self.algorithm != self.signer_public_key.algorithm()
            || self.algorithm != self.signature.algorithm()
        {
            return Err("capability issuance response algorithm mismatch".to_string());
        }
        match (
            self.keyring_artifact_signature.as_ref(),
            self.artifact_time_anchor.as_ref(),
        ) {
            (Some(evidence), Some(anchor))
                if evidence.artifact_signature == self.signature
                    && evidence.artifact_hash == anchor.body.artifact_hash => {}
            (None, None) => {}
            _ => {
                return Err(
                    "capability issuance response keyring evidence is incomplete or mismatched"
                        .to_string(),
                );
            }
        }
        if self.body.request_nonce != expected_request.request_nonce
            || self.body.request_digest != expected_request.binding_digest()?
        {
            return Err("capability issuance response request binding mismatch".to_string());
        }
        if self.body.issued_at > now.saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
            || self.body.expires_at <= now
        {
            return Err(
                "capability issuance response is outside the capability validity window"
                    .to_string(),
            );
        }
        if self.body.capability.issuer != self.signer_public_key {
            return Err(
                "capability issuance response signer does not match the capability issuer"
                    .to_string(),
            );
        }
        let signing_bytes = capability_issuance_response_signing_bytes(
            &self.body,
            &self.signer_public_key,
            self.algorithm,
        )?;
        if !self
            .signer_public_key
            .verify(&signing_bytes, &self.signature)
        {
            return Err("capability issuance response signature is invalid".to_string());
        }
        Ok(())
    }

    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        capability_issuance_response_signing_bytes(
            &self.body,
            &self.signer_public_key,
            self.algorithm,
        )
    }
}

fn capability_issuance_response_signing_bytes(
    body: &CapabilityIssuanceResponseBody,
    signer_public_key: &PublicKey,
    algorithm: SigningAlgorithm,
) -> Result<Vec<u8>, String> {
    let payload = CapabilityIssuanceResponseSigningPayload {
        schema: CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
    let mut bytes =
        Vec::with_capacity(CAPABILITY_ISSUANCE_RESPONSE_SIGNATURE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(CAPABILITY_ISSUANCE_RESPONSE_SIGNATURE_DOMAIN.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_capability_issuance_nonce(nonce: &str) -> Result<(), String> {
    validate_lower_hex_digest(nonce, "capability issuance request nonce")
}

fn validate_lower_hex_digest(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be 64 lowercase hex characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_core::capability::token::CapabilityTokenBody;
    use chio_test_support::prelude::*;

    fn request(now: u64, subject: &PublicKey, issuer: &PublicKey) -> IssueCapabilityRequest {
        let workload_signer = Keypair::generate();
        let session_admission_signer = Keypair::generate();
        IssueCapabilityRequest::new(
            "ab".repeat(32),
            now,
            TenantId::new("tenant-a").test_unwrap(),
            LineageId::new("lineage-a").test_unwrap(),
            "session-a".to_string(),
            "principal-a".to_string(),
            "isolation-a".to_string(),
            1,
            "workload-a".to_string(),
            "server".to_string(),
            issuer.clone(),
            7,
            subject,
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "server".to_string(),
                    tool_name: "tool".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            60,
            None,
            &workload_signer,
            &session_admission_signer,
        )
        .test_unwrap()
    }

    #[test]
    fn signed_capability_issuance_response_binds_the_exact_request() {
        let now = 1_000;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let request = request(now, &subject.public_key(), &issuer.public_key());
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "issued".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: request.scope.clone(),
                issued_at: now,
                expires_at: now + 60,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .test_unwrap();
        let signed =
            SignedIssueCapabilityResponse::sign(&request, capability, &issuer, 7, 900, now)
                .test_unwrap();
        signed
            .verify(&issuer.public_key(), 7, &request, now)
            .test_unwrap();

        let mut changed = request.clone();
        changed.runtime_attestation = Some(RuntimeAttestationEvidence {
            schema: "test.attestation.v1".to_string(),
            verifier: "test-verifier".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now - 1,
            expires_at: now + 10,
            evidence_sha256: "cd".repeat(32),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        });
        assert!(signed
            .verify(&issuer.public_key(), 7, &changed, now)
            .is_err());

        let mut changed_context = request.clone();
        changed_context.tenant_id = TenantId::new("tenant-b").test_unwrap();
        changed_context.lineage_id = LineageId::new("lineage-b").test_unwrap();
        assert!(signed
            .verify(&issuer.public_key(), 7, &changed_context, now)
            .is_err());
    }
}
