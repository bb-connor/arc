use chio_core_types::{
    canonical_json_bytes, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::BrokerExecuteRequest;
use crate::store::{AttemptRegistration, RegisterAttemptOutcome};
use crate::{validate_digest, validate_identifier, BrokerError, Result};

pub const REGISTER_ATTEMPT_AUTHORIZATION_SCHEMA: &str =
    "chio.broker-register-attempt-authorization.v1";
pub const REGISTER_ATTEMPT_ACKNOWLEDGEMENT_SCHEMA: &str =
    "chio.broker-register-attempt-acknowledgement.v1";
pub const RELEASE_ATTEMPT_ACKNOWLEDGEMENT_SCHEMA: &str =
    "chio.broker-release-attempt-acknowledgement.v1";
pub const PREPARE_DISPATCH_ACKNOWLEDGEMENT_SCHEMA: &str =
    "chio.broker-prepare-dispatch-acknowledgement.v1";
const REGISTER_ATTEMPT_AUTHORIZATION_DOMAIN: &str =
    "chio.broker-register-attempt-authorization.v1\0";
const REGISTER_ATTEMPT_DIGEST_DOMAIN: &[u8] = b"chio.broker-register-attempt.v1\0";
const BROKER_EXECUTE_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"chio.broker-execute-request-registration.v1\0";
const PREPARED_DISPATCH_ID_DOMAIN: &[u8] = b"chio.broker-prepared-dispatch.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterAttemptAction {
    Register,
    Prepare,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedAttemptRequest {
    pub registration: AttemptRegistration,
    pub request: BrokerExecuteRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterAttemptAuthorizationBody {
    pub schema: String,
    pub action: RegisterAttemptAction,
    pub tenant_scope: String,
    pub registration_digest: String,
    pub issued_at_unix_seconds: u64,
    pub authority: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedRegisterAttemptAuthorization {
    pub body: RegisterAttemptAuthorizationBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterAttemptDisposition {
    Inserted,
    ExactRetry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterAttemptAcknowledgement {
    pub schema: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub disposition: RegisterAttemptDisposition,
    pub registered_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAttemptAcknowledgement {
    pub schema: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub released_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareDispatchAcknowledgement {
    pub schema: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub prepared_dispatch_id: String,
    pub prepared_at_unix_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegisterAttemptSigningInput<'a> {
    domain: &'static str,
    body: &'a RegisterAttemptAuthorizationBody,
}

pub fn attempt_registration_digest(registration: &AttemptRegistration) -> Result<String> {
    registration.validate()?;
    let canonical = canonical_json_bytes(registration).map_err(|error| {
        BrokerError::Invariant(format!("attempt registration encoding failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(REGISTER_ATTEMPT_DIGEST_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub fn broker_execute_request_registration_digest(
    request: &BrokerExecuteRequest,
) -> Result<String> {
    request.validate_bounds()?;
    let canonical = canonical_json_bytes(request).map_err(|error| {
        BrokerError::Invariant(format!(
            "broker execute registration encoding failed: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(BROKER_EXECUTE_REQUEST_DIGEST_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub fn prepared_dispatch_id(
    registration: &AttemptRegistration,
    request: &BrokerExecuteRequest,
) -> Result<String> {
    let request_canonical_digest = broker_execute_request_registration_digest(request)?;
    if registration.request_canonical_digest != request_canonical_digest {
        return Err(BrokerError::AuthorizationDenied(
            "authenticated registration does not bind the canonical broker request".to_string(),
        ));
    }
    let registration_digest = attempt_registration_digest(registration)?;
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_DISPATCH_ID_DOMAIN);
    hasher.update(registration.ids.operation_id.as_bytes());
    hasher.update([0]);
    hasher.update(registration.ids.attempt_id.as_bytes());
    hasher.update([0]);
    hasher.update(registration_digest.as_bytes());
    hasher.update([0]);
    hasher.update(request_canonical_digest.as_bytes());
    Ok(format!(
        "broker-prepared-dispatch-{}",
        hex::encode(hasher.finalize())
    ))
}

pub fn sign_register_attempt_authorization(
    action: RegisterAttemptAction,
    tenant_scope: String,
    registration: &AttemptRegistration,
    issued_at_unix_seconds: u64,
    signer: &dyn SigningBackend,
) -> Result<SignedRegisterAttemptAuthorization> {
    validate_identifier(&tenant_scope, "register-attempt tenant scope", 512)?;
    if issued_at_unix_seconds == 0 {
        return Err(BrokerError::InvalidRequest(
            "register-attempt authorization time is invalid".to_string(),
        ));
    }
    let expected_authority = signer.public_key();
    let body = RegisterAttemptAuthorizationBody {
        schema: REGISTER_ATTEMPT_AUTHORIZATION_SCHEMA.to_string(),
        action,
        tenant_scope,
        registration_digest: attempt_registration_digest(registration)?,
        issued_at_unix_seconds,
        authority: expected_authority.clone(),
    };
    let signing = RegisterAttemptSigningInput {
        domain: REGISTER_ATTEMPT_AUTHORIZATION_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&signing).map_err(|error| {
        BrokerError::Invariant(format!(
            "register-attempt authorization signing input encoding failed: {error}"
        ))
    })?;
    let signed = signer
        .sign_bytes_for_identity(&expected_authority, &canonical)
        .map_err(|error| {
            BrokerError::Invariant(format!(
                "register-attempt authorization signing failed: {error}"
            ))
        })?;
    if signed.public_key != expected_authority
        || signed.algorithm != expected_authority.algorithm()
        || signed.signature.algorithm() != signed.algorithm
        || !signed.public_key.verify(&canonical, &signed.signature)
    {
        return Err(BrokerError::Invariant(
            "register-attempt signing backend returned a mismatched identity or signature"
                .to_string(),
        ));
    }
    Ok(SignedRegisterAttemptAuthorization {
        algorithm: signed.algorithm,
        body,
        signature: signed.signature,
    })
}

pub fn verify_register_attempt_authorization(
    authorization: &SignedRegisterAttemptAuthorization,
    registration: &AttemptRegistration,
    expected_action: RegisterAttemptAction,
    tenant_scope: &str,
    trusted_authority: &PublicKey,
    now_unix_seconds: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<()> {
    validate_identifier(tenant_scope, "register-attempt tenant scope", 512)?;
    validate_digest(
        &authorization.body.registration_digest,
        "register-attempt registration digest",
    )?;
    if authorization.body.schema != REGISTER_ATTEMPT_AUTHORIZATION_SCHEMA
        || authorization.body.action != expected_action
        || authorization.body.tenant_scope != tenant_scope
        || &authorization.body.authority != trusted_authority
        || authorization.algorithm != trusted_authority.algorithm()
        || authorization.signature.algorithm() != authorization.algorithm
        || authorization.body.registration_digest != attempt_registration_digest(registration)?
    {
        return Err(BrokerError::AuthorizationDenied(
            "register-attempt authorization binding is invalid".to_string(),
        ));
    }
    let earliest = authorization
        .body
        .issued_at_unix_seconds
        .saturating_sub(maximum_clock_skew_seconds);
    let latest = authorization
        .body
        .issued_at_unix_seconds
        .checked_add(maximum_clock_skew_seconds)
        .ok_or_else(|| {
            BrokerError::AuthorizationDenied(
                "register-attempt authorization time overflowed".to_string(),
            )
        })?;
    if now_unix_seconds < earliest || now_unix_seconds > latest {
        return Err(BrokerError::AuthorizationDenied(
            "register-attempt authorization is stale or from the future".to_string(),
        ));
    }
    let signing = RegisterAttemptSigningInput {
        domain: REGISTER_ATTEMPT_AUTHORIZATION_DOMAIN,
        body: &authorization.body,
    };
    let verified = trusted_authority
        .verify_canonical(&signing, &authorization.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "register-attempt authorization verification failed: {error}"
            ))
        })?;
    if !verified {
        return Err(BrokerError::AuthorizationDenied(
            "register-attempt authorization signature is invalid".to_string(),
        ));
    }
    Ok(())
}

impl RegisterAttemptAcknowledgement {
    pub fn from_outcome(
        outcome: RegisterAttemptOutcome,
        registered_at_unix_seconds: u64,
    ) -> Result<Self> {
        let (disposition, record) = match outcome {
            RegisterAttemptOutcome::Inserted(record) => {
                (RegisterAttemptDisposition::Inserted, record)
            }
            RegisterAttemptOutcome::ExactRetry(record) => {
                (RegisterAttemptDisposition::ExactRetry, record)
            }
        };
        if registered_at_unix_seconds == 0 {
            return Err(BrokerError::Invariant(
                "register-attempt acknowledgement time is invalid".to_string(),
            ));
        }
        Ok(Self {
            schema: REGISTER_ATTEMPT_ACKNOWLEDGEMENT_SCHEMA.to_string(),
            operation_id: record.registration.ids.operation_id,
            attempt_id: record.registration.ids.attempt_id,
            disposition,
            registered_at_unix_seconds,
        })
    }

    pub fn validate_for(&self, registration: &AttemptRegistration) -> Result<()> {
        if self.schema != REGISTER_ATTEMPT_ACKNOWLEDGEMENT_SCHEMA
            || self.operation_id != registration.ids.operation_id
            || self.attempt_id != registration.ids.attempt_id
            || self.registered_at_unix_seconds == 0
        {
            return Err(BrokerError::AuthorityUnavailable(
                "register-attempt acknowledgement is malformed or misbound".to_string(),
            ));
        }
        Ok(())
    }
}

impl ReleaseAttemptAcknowledgement {
    pub fn new(registration: &AttemptRegistration, released_at_unix_seconds: u64) -> Result<Self> {
        registration.validate()?;
        if released_at_unix_seconds == 0 {
            return Err(BrokerError::Invariant(
                "release-attempt acknowledgement time is invalid".to_string(),
            ));
        }
        Ok(Self {
            schema: RELEASE_ATTEMPT_ACKNOWLEDGEMENT_SCHEMA.to_string(),
            operation_id: registration.ids.operation_id.clone(),
            attempt_id: registration.ids.attempt_id.clone(),
            released_at_unix_seconds,
        })
    }

    pub fn validate_for(&self, registration: &AttemptRegistration) -> Result<()> {
        if self.schema != RELEASE_ATTEMPT_ACKNOWLEDGEMENT_SCHEMA
            || self.operation_id != registration.ids.operation_id
            || self.attempt_id != registration.ids.attempt_id
            || self.released_at_unix_seconds == 0
        {
            return Err(BrokerError::AuthorityUnavailable(
                "release-attempt acknowledgement is malformed or misbound".to_string(),
            ));
        }
        Ok(())
    }
}

impl PrepareDispatchAcknowledgement {
    pub fn new(
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
        prepared_at_unix_seconds: u64,
    ) -> Result<Self> {
        if prepared_at_unix_seconds == 0 {
            return Err(BrokerError::Invariant(
                "prepare-dispatch acknowledgement time is invalid".to_string(),
            ));
        }
        Ok(Self {
            schema: PREPARE_DISPATCH_ACKNOWLEDGEMENT_SCHEMA.to_string(),
            operation_id: registration.ids.operation_id.clone(),
            attempt_id: registration.ids.attempt_id.clone(),
            prepared_dispatch_id: prepared_dispatch_id(registration, request)?,
            prepared_at_unix_seconds,
        })
    }

    pub fn validate_for(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> Result<()> {
        if self.schema != PREPARE_DISPATCH_ACKNOWLEDGEMENT_SCHEMA
            || self.operation_id != registration.ids.operation_id
            || self.attempt_id != registration.ids.attempt_id
            || self.prepared_dispatch_id != prepared_dispatch_id(registration, request)?
            || self.prepared_at_unix_seconds == 0
        {
            return Err(BrokerError::AuthorityUnavailable(
                "prepare-dispatch acknowledgement is malformed or misbound".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::ExecutionQuota;
    use crate::store::derive_attempt_ids;
    use chio_core_types::{Ed25519Backend, Keypair};
    use chio_test_support::prelude::*;

    fn registration() -> AttemptRegistration {
        let request_digest = "a".repeat(64);
        AttemptRegistration {
            ids: derive_attempt_ids(
                "broker-capability",
                "invocation",
                "nonce-abcdefghijkl",
                &request_digest,
            )
            .test_expect("ids"),
            invocation_id: "invocation".to_string(),
            parent_capability_id: "parent-capability".to_string(),
            broker_capability_id: "broker-capability".to_string(),
            request_digest,
            request_canonical_digest: "d".repeat(64),
            proof_digest: "b".repeat(64),
            proof_key_id: "proof-key".to_string(),
            proof_nonce: "nonce-abcdefghijkl".to_string(),
            nonce_expires_at_unix_seconds: 200,
            quotas: vec![ExecutionQuota {
                key_id: "quota".to_string(),
                maximum_executions: 1,
            }],
            authority_metadata_digest: "c".repeat(64),
            revocation_authority_domain: "combined-authority".to_string(),
        }
    }

    #[test]
    fn registration_authorization_binds_tenant_payload_time_and_authority() {
        let signer = Keypair::from_seed(&[71; 32]);
        let backend = Ed25519Backend::new(signer.clone());
        let registration = registration();
        let authorization = sign_register_attempt_authorization(
            RegisterAttemptAction::Register,
            "tenant-a".to_string(),
            &registration,
            100,
            &backend,
        )
        .test_expect("authorization");
        verify_register_attempt_authorization(
            &authorization,
            &registration,
            RegisterAttemptAction::Register,
            "tenant-a",
            &signer.public_key(),
            101,
            5,
        )
        .test_expect("verification");
        assert!(verify_register_attempt_authorization(
            &authorization,
            &registration,
            RegisterAttemptAction::Register,
            "tenant-b",
            &signer.public_key(),
            101,
            5,
        )
        .is_err());
        assert!(verify_register_attempt_authorization(
            &authorization,
            &registration,
            RegisterAttemptAction::Register,
            "tenant-a",
            &signer.public_key(),
            106,
            5,
        )
        .is_err());
    }
}
