use chio_core_types::{canonical_json_bytes, Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{
    BrokerDestination, BrokerRequest, CallerOptions, CredentialRef, HeaderField,
    SignedBrokerCapability, BROKER_PROOF_SCHEMA, MAX_NONCE_BYTES,
};
use crate::{validate_digest, BrokerError, Result};

const PROOF_SIGNATURE_DOMAIN: &str = "chio.broker-request-proof-signature.v1\0";
const HEADER_DIGEST_DOMAIN: &[u8] = b"chio.broker-caller-headers.v1\0";
const OPTION_DIGEST_DOMAIN: &[u8] = b"chio.broker-caller-options.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestProofBody {
    pub schema: String,
    pub broker_capability_id: String,
    pub parent_capability_id: String,
    pub credential: CredentialRef,
    pub capability_expires_at_unix_seconds: u64,
    pub destination: BrokerDestination,
    pub body_sha256: String,
    pub caller_headers_sha256: String,
    pub caller_options_sha256: String,
    pub nonce: String,
    pub issued_at_unix_seconds: u64,
    pub authority_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestProof {
    pub body: RequestProofBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofSigningInput<'a> {
    domain: &'static str,
    body: &'a RequestProofBody,
}

pub fn issue_request_proof(
    capability: &SignedBrokerCapability,
    request: &BrokerRequest,
    nonce: String,
    issued_at_unix_seconds: u64,
    signer: &Keypair,
) -> Result<RequestProof> {
    request.validate_bounds()?;
    validate_nonce(&nonce)?;
    if signer.public_key() != capability.body.proof.caller_public_key {
        return Err(BrokerError::AuthorizationDenied(
            "proof signer does not match capability proof key".to_string(),
        ));
    }
    let body = RequestProofBody {
        schema: BROKER_PROOF_SCHEMA.to_string(),
        broker_capability_id: capability.body.capability_id.clone(),
        parent_capability_id: capability.body.parent_capability_id.clone(),
        credential: capability.body.credential.clone(),
        capability_expires_at_unix_seconds: capability.body.expires_at_unix_seconds,
        destination: request.destination.clone(),
        body_sha256: body_digest(&request.body),
        caller_headers_sha256: caller_header_digest(&request.headers)?,
        caller_options_sha256: caller_option_digest(&request.options)?,
        nonce,
        issued_at_unix_seconds,
        authority_key: signer.public_key(),
    };
    let signing = ProofSigningInput {
        domain: PROOF_SIGNATURE_DOMAIN,
        body: &body,
    };
    let (signature, _) = signer
        .sign_canonical(&signing)
        .map_err(|error| BrokerError::Invariant(format!("proof signing failed: {error}")))?;
    Ok(RequestProof {
        body,
        algorithm: signer.public_key().algorithm(),
        signature,
    })
}

pub fn verify_request_proof(
    proof: &RequestProof,
    capability: &SignedBrokerCapability,
    request: &BrokerRequest,
    now_unix_seconds: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<()> {
    request.validate_bounds()?;
    if proof.body.schema != BROKER_PROOF_SCHEMA {
        return Err(BrokerError::AuthorizationDenied(
            "unsupported request proof schema".to_string(),
        ));
    }
    validate_nonce(&proof.body.nonce)?;
    for (digest, label) in [
        (&proof.body.body_sha256, "proof body digest"),
        (&proof.body.caller_headers_sha256, "proof header digest"),
        (&proof.body.caller_options_sha256, "proof option digest"),
    ] {
        validate_digest(digest, label)?;
    }
    let latest = proof
        .body
        .issued_at_unix_seconds
        .checked_add(capability.body.proof.nonce_ttl_seconds)
        .ok_or_else(|| BrokerError::AuthorizationDenied("proof lifetime overflow".to_string()))?;
    let future_limit = now_unix_seconds
        .checked_add(maximum_clock_skew_seconds)
        .ok_or_else(|| BrokerError::AuthorizationDenied("proof clock overflow".to_string()))?;
    if proof.body.issued_at_unix_seconds < capability.body.not_before_unix_seconds
        || proof.body.issued_at_unix_seconds >= capability.body.expires_at_unix_seconds
        || proof.body.issued_at_unix_seconds > future_limit
        || now_unix_seconds > latest
    {
        return Err(BrokerError::AuthorizationDenied(
            "request proof is outside the capability interval, stale, or from the future"
                .to_string(),
        ));
    }
    if proof.body.broker_capability_id != capability.body.capability_id
        || proof.body.parent_capability_id != capability.body.parent_capability_id
        || proof.body.credential != capability.body.credential
        || proof.body.capability_expires_at_unix_seconds != capability.body.expires_at_unix_seconds
        || proof.body.destination != request.destination
        || proof.body.body_sha256 != body_digest(&request.body)
        || proof.body.caller_headers_sha256 != caller_header_digest(&request.headers)?
        || proof.body.caller_options_sha256 != caller_option_digest(&request.options)?
        || proof.body.authority_key != capability.body.proof.caller_public_key
        || proof.algorithm != proof.body.authority_key.algorithm()
        || proof.signature.algorithm() != proof.algorithm
    {
        return Err(BrokerError::AuthorizationDenied(
            "request proof does not bind the complete request".to_string(),
        ));
    }
    let signing = ProofSigningInput {
        domain: PROOF_SIGNATURE_DOMAIN,
        body: &proof.body,
    };
    let valid = proof
        .body
        .authority_key
        .verify_canonical(&signing, &proof.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!("proof verification failed: {error}"))
        })?;
    if !valid {
        return Err(BrokerError::AuthorizationDenied(
            "request proof signature is invalid".to_string(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn caller_header_digest(headers: &[HeaderField]) -> Result<String> {
    let canonical = canonical_json_bytes(&headers)
        .map_err(|error| BrokerError::Invariant(format!("header digest failed: {error}")))?;
    Ok(domain_digest(HEADER_DIGEST_DOMAIN, &canonical))
}

pub fn caller_option_digest(options: &CallerOptions) -> Result<String> {
    let canonical = canonical_json_bytes(options)
        .map_err(|error| BrokerError::Invariant(format!("option digest failed: {error}")))?;
    Ok(domain_digest(OPTION_DIGEST_DOMAIN, &canonical))
}

pub fn proof_digest(proof: &RequestProof) -> Result<String> {
    let canonical = canonical_json_bytes(proof)
        .map_err(|error| BrokerError::Invariant(format!("proof digest failed: {error}")))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.len() < 16
        || nonce.len() > MAX_NONCE_BYTES
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(BrokerError::InvalidRequest(
            "proof nonce has invalid length or characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::capability::issue_capability;
    use crate::protocol::{
        AttemptConsumption, BrokerCapabilityBody, BrokerDestination, CallerOptions, CredentialRef,
        HeaderField, ProofBinding, ProofMode, RedirectPolicy, RequestConstraints,
        BROKER_CAPABILITY_SCHEMA,
    };

    fn fixture() -> (Keypair, SignedBrokerCapability, BrokerRequest) {
        let issuer = Keypair::from_seed(&[1; 32]);
        let caller = Keypair::from_seed(&[2; 32]);
        let destination = BrokerDestination::parse("https://example.com/v1?x=1", "post", false)
            .expect("destination");
        let request = BrokerRequest {
            destination: destination.clone(),
            headers: vec![
                HeaderField::normalized("content-type", b"application/json").expect("header")
            ],
            body: b"body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: 1_000,
                streaming: false,
                response_limit_bytes: 256,
            },
        };
        let body = BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.to_string(),
            issuer: issuer.public_key(),
            capability_id: "broker-capability-1".to_string(),
            parent_capability_id: "parent-capability-1".to_string(),
            subject: caller.public_key(),
            audience: "broker-service".to_string(),
            issued_at_unix_seconds: 10,
            not_before_unix_seconds: 10,
            expires_at_unix_seconds: 100,
            credential: CredentialRef {
                provider: "generic-https".to_string(),
                credential_id: "credential-a".to_string(),
                version: 1,
            },
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            destination,
            constraints: RequestConstraints {
                allowed_caller_headers: vec!["content-type".to_string()],
                provider_owned_headers: vec!["authorization".to_string()],
                maximum_body_bytes: 128,
                required_body_sha256: hex::encode(Sha256::digest(b"body")),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 256,
                streaming_allowed: false,
                maximum_timeout_ms: 1_000,
            },
            broker_quota_key_id: "broker-quota-1".to_string(),
            maximum_executions: 2,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "broker-revocation-1".to_string(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: caller.public_key(),
                nonce_ttl_seconds: 30,
            },
        };
        let capability = issue_capability(body, &issuer, true).expect("capability");
        (caller, capability, request)
    }

    #[test]
    fn proof_binds_headers_body_options_destination_and_credential_version() {
        let (caller, capability, request) = fixture();
        let proof = issue_request_proof(
            &capability,
            &request,
            "nonce-abcdefghijkl".to_string(),
            20,
            &caller,
        )
        .expect("proof");
        verify_request_proof(&proof, &capability, &request, 21, 2).expect("verify");

        let mut changed = request.clone();
        changed.options.streaming = true;
        assert!(verify_request_proof(&proof, &capability, &changed, 21, 2).is_err());
        let mut changed = request;
        changed.headers[0].value = b"text/plain".to_vec();
        assert!(verify_request_proof(&proof, &capability, &changed, 21, 2).is_err());
    }
}
