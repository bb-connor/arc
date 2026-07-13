use chio_core_types::{canonical_json_bytes, Keypair};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::protocol::{BrokerCapabilityBody, SignedBrokerCapability};
use crate::{BrokerError, Result};

const CAPABILITY_SIGNATURE_DOMAIN: &str = "chio.broker-capability-signature.v1\0";

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapabilitySigningInput<'a> {
    domain: &'static str,
    body: &'a BrokerCapabilityBody,
}

pub fn issue_capability(
    body: BrokerCapabilityBody,
    signer: &Keypair,
    production: bool,
) -> Result<SignedBrokerCapability> {
    body.validate(production)?;
    if body.issuer != signer.public_key() {
        return Err(BrokerError::AuthorizationDenied(
            "capability issuer does not match the signing key".to_string(),
        ));
    }
    let input = CapabilitySigningInput {
        domain: CAPABILITY_SIGNATURE_DOMAIN,
        body: &body,
    };
    let (signature, _) = signer
        .sign_canonical(&input)
        .map_err(|error| BrokerError::Invariant(format!("capability signing failed: {error}")))?;
    Ok(SignedBrokerCapability {
        body,
        algorithm: signer.public_key().algorithm(),
        signature,
    })
}

pub fn verify_capability(
    capability: &SignedBrokerCapability,
    trusted_issuer: &chio_core_types::PublicKey,
    audience: &str,
    now_unix_seconds: u64,
    production: bool,
) -> Result<()> {
    capability.body.validate(production)?;
    if &capability.body.issuer != trusted_issuer
        || capability.body.issuer.algorithm() != capability.algorithm
        || capability.signature.algorithm() != capability.algorithm
        || capability.body.audience != audience
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker capability issuer, algorithm, or audience is invalid".to_string(),
        ));
    }
    if now_unix_seconds < capability.body.not_before_unix_seconds
        || now_unix_seconds >= capability.body.expires_at_unix_seconds
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker capability is outside its validity interval".to_string(),
        ));
    }
    let input = CapabilitySigningInput {
        domain: CAPABILITY_SIGNATURE_DOMAIN,
        body: &capability.body,
    };
    let valid = trusted_issuer
        .verify_canonical(&input, &capability.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!("capability verification failed: {error}"))
        })?;
    if !valid {
        return Err(BrokerError::AuthorizationDenied(
            "broker capability signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub fn capability_digest(capability: &SignedBrokerCapability) -> Result<String> {
    let canonical = canonical_json_bytes(capability).map_err(|error| {
        BrokerError::Invariant(format!("capability canonicalization failed: {error}"))
    })?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

#[cfg(test)]
mod tests {
    use chio_core_types::Keypair;

    use super::*;
    use crate::protocol::{
        AttemptConsumption, BrokerDestination, BrokerScheme, CredentialRef, ProofBinding,
        ProofMode, RedirectPolicy, RequestConstraints, BROKER_CAPABILITY_SCHEMA,
    };

    fn body(signer: &Keypair) -> BrokerCapabilityBody {
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.to_string(),
            issuer: signer.public_key(),
            capability_id: "broker-capability-1".to_string(),
            parent_capability_id: "parent-capability-1".to_string(),
            subject: Keypair::from_seed(&[2; 32]).public_key(),
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
            destination: BrokerDestination {
                scheme: BrokerScheme::Https,
                normalized_host: "example.com".to_string(),
                explicit_port: 443,
                exact_path_and_query: "/v1?x=1".to_string(),
                method: "POST".to_string(),
            },
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
                caller_public_key: Keypair::from_seed(&[2; 32]).public_key(),
                nonce_ttl_seconds: 30,
            },
        }
    }

    #[test]
    fn every_body_byte_is_covered_by_canonical_signature() {
        let signer = Keypair::from_seed(&[1; 32]);
        let capability = issue_capability(body(&signer), &signer, true).expect("issue");
        verify_capability(
            &capability,
            &signer.public_key(),
            "broker-service",
            20,
            true,
        )
        .expect("verify");
        let mut changed = capability.clone();
        changed.body.destination.exact_path_and_query = "/other".to_string();
        assert!(
            verify_capability(&changed, &signer.public_key(), "broker-service", 20, true).is_err()
        );
    }
}
