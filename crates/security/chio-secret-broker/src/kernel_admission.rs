//! Composition-installed verification of broker requests before kernel quota custody.
//!
//! This verifier never materializes a credential, reserves a broker-local quota,
//! consumes a proof or authorizes dispatch. The kernel retains the resulting
//! supplemental claim with its original operation and composite budget hold.

use std::sync::Arc;

use chio_core_types::{canonical_json_bytes, PublicKey};
use chio_kernel::supplemental_quota::{
    supplemental_authorization_artifact_digest, supplemental_request_binding_hash,
    SupplementalQuotaVerificationContext, SupplementalQuotaVerifier,
    SupplementalQuotaVerifierBinding, SupplementalQuotaVerifierError,
    VerifiedSupplementalQuotaClaim, BROKER_CAPABILITY_EXECUTION_PROFILE,
    MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::daemon::DaemonClock;
use crate::daemon_runtime::ProviderPlacementConfig;
use crate::protocol::BrokerExecuteRequest;
use crate::provider::{CredentialPlacement, GenericCredentialProvider};
use crate::{validate_identifier, BrokerError, Result};

const VERIFIER_ID: &str = "chio.secret-broker.kernel-quota-verifier.v1";

mod registration;
pub use registration::BrokerAdmissionParticipant;
mod capture;
pub use capture::BrokerNativeCaptureReader;

/// Independently installed trust and tool routing. An artifact cannot select
/// its issuer, provider adapter, clock or kernel destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerQuotaVerifierConfig {
    pub issuer: PublicKey,
    pub audience: String,
    pub server_id: String,
    pub tool_name: String,
    pub provider_adapter_id: String,
    pub provider_adapter_version: u32,
    pub credential_placement: ProviderPlacementConfig,
}

pub struct BrokerQuotaVerifier {
    config: BrokerQuotaVerifierConfig,
    clock: Arc<dyn DaemonClock>,
    binding: SupplementalQuotaVerifierBinding,
    normalized_destination: String,
    provider: GenericCredentialProvider,
}

impl BrokerQuotaVerifier {
    pub fn new(config: BrokerQuotaVerifierConfig, clock: Arc<dyn DaemonClock>) -> Result<Self> {
        for field in [
            &config.audience,
            &config.server_id,
            &config.tool_name,
            &config.provider_adapter_id,
        ] {
            validate_identifier(field, "broker verifier configuration", 512)?;
        }
        let provider = GenericCredentialProvider::new(
            config.provider_adapter_id.clone(),
            config.provider_adapter_version,
            match config.credential_placement {
                ProviderPlacementConfig::BearerAuthorization => {
                    CredentialPlacement::BearerAuthorization
                }
                ProviderPlacementConfig::ApiKeyHeader => CredentialPlacement::ApiKeyHeader,
            },
        )?;
        let bytes = canonical(&config)?;
        let binding = SupplementalQuotaVerifierBinding {
            verifier_identity: VERIFIER_ID.into(),
            configuration_digest: hex::encode(Sha256::digest(bytes)),
        };
        let normalized_destination = String::from_utf8(canonical(&serde_json::json!({
            "server_id": config.server_id, "tool_name": config.tool_name,
        }))?)
        .map_err(|_| rejected())?;
        Ok(Self {
            config,
            clock,
            binding,
            normalized_destination,
            provider,
        })
    }

    #[must_use]
    pub fn binding(&self) -> &SupplementalQuotaVerifierBinding {
        &self.binding
    }

    fn verify_request(
        &self,
        bytes: &[u8],
        context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaim> {
        if bytes.is_empty()
            || bytes.len() > MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES
            || context.verifier_binding != self.binding
            || context.normalized_destination != self.normalized_destination
            || context.negotiated_profile != BROKER_CAPABILITY_EXECUTION_PROFILE
            || !context
                .negotiated_features
                .supports(BROKER_CAPABILITY_EXECUTION_PROFILE)
        {
            return Err(rejected());
        }
        let execute: BrokerExecuteRequest =
            serde_json::from_slice(bytes).map_err(|_| rejected())?;
        // Exact typed canonical bytes reject duplicate fields, unknown options
        // and alternate encodings. Every behavior-affecting request byte is
        // also bound by the kernel's independently computed argument digest.
        if canonical(&execute)? != bytes
            || hex::encode(Sha256::digest(bytes)) != context.arguments_hash
        {
            return Err(rejected());
        }
        execute.validate_bounds()?;
        let body = &execute.capability.body;
        if execute.invocation_id != context.request_id
            || body.parent_capability_id != context.capability_id
            || body.subject != context.subject
            || body.provider_adapter_id != self.config.provider_adapter_id
            || body.provider_adapter_version != self.config.provider_adapter_version
            || execute.request.destination != body.destination
        {
            return Err(rejected());
        }
        let now = self.clock.now_unix_seconds()?;
        crate::capability::verify_capability(
            &execute.capability,
            &self.config.issuer,
            &self.config.audience,
            now,
            true,
        )?;
        // Admission uses live time and accepts no future-dated proof. This
        // verifies possession only; the broker's durable attempt owns replay.
        crate::proof::verify_request_proof(
            &execute.proof,
            &execute.capability,
            &execute.request,
            now,
            0,
        )?;
        self.provider
            .validate_request(&execute.request, &body.constraints)?;
        crate::generic_https::validate_request_before_secret_use(
            &execute.request,
            &body.constraints,
        )?;
        let expires_at = execute
            .proof
            .body
            .issued_at_unix_seconds
            .checked_add(body.proof.nonce_ttl_seconds)
            .ok_or_else(rejected)?
            .min(body.expires_at_unix_seconds);
        if now >= expires_at {
            return Err(rejected());
        }
        let mut revocations = vec![body.capability_id.clone(), body.revocation_id.clone()];
        revocations.sort_unstable();
        Ok(VerifiedSupplementalQuotaClaim {
            profile: BROKER_CAPABILITY_EXECUTION_PROFILE.into(),
            broker_capability_id: body.capability_id.clone(),
            issuer: body.issuer.clone(),
            // Invocation IDs and proof nonces must not create fresh quota owners.
            request_constraint_digest: hex::encode(Sha256::digest(canonical(body)?)),
            max_invocations: body.maximum_executions,
            authorization_artifact_digest: supplemental_authorization_artifact_digest(bytes),
            supplemental_revocation_ids: revocations,
            expires_at,
            request_binding_hash: supplemental_request_binding_hash(context)
                .map_err(|_| rejected())?,
            capability_id: context.capability_id.clone(),
            capability_digest: context.capability_digest.clone(),
            request_namespace_digest: context.request_namespace_digest.clone(),
            operation_id: context.operation_id.clone(),
            subject: context.subject.clone(),
            request_id: context.request_id.clone(),
            normalized_destination: context.normalized_destination.clone(),
            arguments_hash: context.arguments_hash.clone(),
            negotiated_features: context.negotiated_features.clone(),
        })
    }
}

impl SupplementalQuotaVerifier for BrokerQuotaVerifier {
    fn verify(
        &self,
        bytes: &[u8],
        context: &SupplementalQuotaVerificationContext,
    ) -> std::result::Result<VerifiedSupplementalQuotaClaim, SupplementalQuotaVerifierError> {
        self.verify_request(bytes, context)
            .map_err(|error| SupplementalQuotaVerifierError::new(error.diagnostic_code()))
    }
}

fn rejected() -> BrokerError {
    BrokerError::AuthorizationDenied(
        "broker request differs from installed kernel authority".into(),
    )
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    canonical_json_bytes(value).map_err(|_| rejected())
}

#[cfg(test)]
mod tests;
