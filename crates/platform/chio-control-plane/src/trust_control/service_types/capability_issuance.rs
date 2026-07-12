use chio_core::{
    canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm,
};
use serde::{Deserialize, Serialize};

use super::super::*;

pub(crate) const CAPABILITY_ISSUANCE_REQUEST_SCHEMA: &str = "chio.capability-issuance-request.v1";
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_SCHEMA: &str = "chio.capability-issuance-response.v1";
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_ENVELOPE_SCHEMA: &str =
    "chio.capability-issuance-response-envelope.v1";
const CAPABILITY_ISSUANCE_REQUEST_DIGEST_DOMAIN: &str = "chio.capability-issuance-request.v1\0";
const CAPABILITY_ISSUANCE_RESPONSE_SIGNATURE_DOMAIN: &str =
    "chio.capability-issuance-response-envelope.v1\0";
pub(crate) const CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS: u64 = 60;
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_TTL_SECS: u64 = 30;
pub(crate) const CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssueCapabilityRequest {
    pub(crate) schema: String,
    pub(crate) request_nonce: String,
    pub(crate) requested_at: u64,
    pub(crate) subject_public_key: String,
    pub(crate) scope: ChioScope,
    pub(crate) ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_attestation: Option<RuntimeAttestationEvidence>,
}

impl IssueCapabilityRequest {
    pub(crate) fn new(
        request_nonce: String,
        requested_at: u64,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Self {
        Self {
            schema: CAPABILITY_ISSUANCE_REQUEST_SCHEMA.to_string(),
            request_nonce,
            requested_at,
            subject_public_key: subject.to_hex(),
            scope,
            ttl_seconds,
            runtime_attestation,
        }
    }

    pub(crate) fn validate_at(&self, now: u64) -> Result<(), String> {
        if self.schema != CAPABILITY_ISSUANCE_REQUEST_SCHEMA {
            return Err("capability issuance request schema mismatch".to_string());
        }
        validate_capability_issuance_nonce(&self.request_nonce)?;
        if self.requested_at > now.saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
            || self.requested_at < now.saturating_sub(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        {
            return Err("capability issuance request is outside the freshness window".to_string());
        }
        PublicKey::from_hex(&self.subject_public_key)
            .map_err(|_| "capability issuance subject public key is invalid".to_string())?;
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

    pub(crate) fn binding_digest(&self) -> Result<String, String> {
        let canonical = canonical_json_bytes(self).map_err(|error| error.to_string())?;
        let mut preimage =
            Vec::with_capacity(CAPABILITY_ISSUANCE_REQUEST_DIGEST_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(CAPABILITY_ISSUANCE_REQUEST_DIGEST_DOMAIN.as_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(sha256_hex(&preimage))
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
        let lifetime = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or_else(|| "capability issuance response expiry precedes issuance".to_string())?;
        if lifetime == 0 || lifetime > CAPABILITY_ISSUANCE_RESPONSE_TTL_SECS {
            return Err("capability issuance response lifetime is invalid".to_string());
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
        let expires_at = issued_at
            .checked_add(CAPABILITY_ISSUANCE_RESPONSE_TTL_SECS)
            .ok_or_else(|| "capability issuance response expiry overflow".to_string())?;
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
        })
    }

    pub(crate) fn verify(
        &self,
        expected_signer: &PublicKey,
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
        if self.algorithm != self.signer_public_key.algorithm()
            || self.algorithm != self.signature.algorithm()
        {
            return Err("capability issuance response algorithm mismatch".to_string());
        }
        if self.body.request_nonce != expected_request.request_nonce
            || self.body.request_digest != expected_request.binding_digest()?
        {
            return Err("capability issuance response request binding mismatch".to_string());
        }
        if self.body.issued_at > now.saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
            || self.body.expires_at <= now.saturating_sub(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        {
            return Err("capability issuance response is outside the freshness window".to_string());
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

    fn request(now: u64, subject: &PublicKey) -> IssueCapabilityRequest {
        IssueCapabilityRequest::new(
            "ab".repeat(32),
            now,
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
        )
    }

    #[test]
    fn signed_capability_issuance_response_binds_the_exact_request() {
        let now = 1_000;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let request = request(now, &subject.public_key());
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
            .verify(&issuer.public_key(), &request, now)
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
        assert!(signed.verify(&issuer.public_key(), &changed, now).is_err());
    }
}
