//! Authenticated registration of the kernel's original attempt before a hold.
use super::{canonical, rejected, BrokerQuotaVerifier};
use crate::budget::{canonicalize_quotas, ExecutionQuota};
use crate::ipc_client::{BrokerIpcClient, BrokerIpcClientConfig};
use crate::protocol::BrokerExecuteRequest;
use crate::registration::broker_execute_request_registration_digest;
use crate::service::broker_request_digest;
use crate::store::{derive_attempt_ids_for_operation, AttemptRegistration};
use crate::{validate_identifier, Result};
use chio_core_types::{PublicKey, Signature, SigningAlgorithm, SigningBackend, SigningOutcome};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingV1,
};
use chio_kernel::budget_store::{BudgetInvocationQuota, BudgetQuotaProfile};
use chio_kernel::supplemental_admission::{
    SupplementalAdmissionAuthorityBindingV1, SupplementalAdmissionParticipant,
    SupplementalAdmissionRegistrationContext,
};
use chio_kernel::supplemental_quota::SupplementalQuotaVerifierError;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const PARTICIPANT_ID: &str = "chio.secret-broker.kernel-registration.v1";

/// Production IPC registration only. The existing kernel still owns quota
/// capture; provider preparation and execution require their separate ports.
pub struct BrokerAdmissionParticipant {
    pub(super) client: BrokerIpcClient,
    revocation_authority_domain: String,
    binding: SupplementalAdmissionAuthorityBindingV1,
    pub(super) server_id: String,
    pub(super) tool_name: String,
    pub(super) audience: String,
}

impl BrokerAdmissionParticipant {
    /// All endpoint, peer, tenant and signing selections come from composition,
    /// never from the submitted broker request or retained history.
    pub fn new(
        config: BrokerIpcClientConfig,
        authority_signer: Arc<dyn SigningBackend>,
        revocation_authority_domain: String,
        verifier: &BrokerQuotaVerifier,
    ) -> Result<Self> {
        validate_identifier(
            &revocation_authority_domain,
            "revocation authority domain",
            512,
        )?;
        let authority_key = authority_signer.public_key();
        let configuration = canonical(&serde_json::json!({
            "schema": PARTICIPANT_ID,
            "socket_path": config.socket_path.to_str().ok_or_else(rejected)?,
            "tenant_scope": config.tenant_scope,
            "timeout_ms": config.timeout_ms,
            "expected_peer": config.expected_peer,
            "trusted_receipt_signer": config.trusted_receipt_signer,
            "authority_signer": authority_key,
            "revocation_authority_domain": revocation_authority_domain,
            "verifier_identity": verifier.binding().verifier_identity,
            "verifier_configuration_digest": verifier.binding().configuration_digest,
        }))?;
        let binding = SupplementalAdmissionAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("participant identity", PARTICIPANT_ID)
                .map_err(|_| rejected())?,
            AdmissionDigest::try_new(
                "participant configuration",
                hex::encode(Sha256::digest(configuration)),
            )
            .map_err(|_| rejected())?,
            AdmissionIdentifier::try_new(
                "verifier identity",
                &verifier.binding().verifier_identity,
            )
            .map_err(|_| rejected())?,
            AdmissionDigest::try_new(
                "verifier configuration",
                &verifier.binding().configuration_digest,
            )
            .map_err(|_| rejected())?,
        );
        // A rotating signer cannot silently change the authority generation
        // pinned above. Identity-qualified signing retains the backend's lease.
        let client = BrokerIpcClient::new(
            config,
            Arc::new(RegistrationSigner {
                inner: authority_signer,
                key: authority_key,
            }),
        )?;
        Ok(Self {
            client,
            revocation_authority_domain,
            binding,
            server_id: verifier.config.server_id.clone(),
            tool_name: verifier.config.tool_name.clone(),
            audience: verifier.config.audience.clone(),
        })
    }

    #[must_use]
    pub fn binding(&self) -> &SupplementalAdmissionAuthorityBindingV1 {
        &self.binding
    }

    pub(super) fn revocation_authority_domain(&self) -> &str {
        &self.revocation_authority_domain
    }

    fn register(&self, context: &SupplementalAdmissionRegistrationContext<'_>) -> Result<()> {
        let request: BrokerExecuteRequest =
            serde_json::from_value(context.request().arguments.clone()).map_err(|_| rejected())?;
        request.validate_bounds()?;
        let operation = context.operation().binding();
        if canonical(&request)? != canonical(&context.request().arguments)?
            || request.invocation_id != operation.request_id().as_str()
            || request.capability.body.parent_capability_id != operation.capability_id().as_str()
            || context.budget().capability_id != operation.capability_id().as_str()
        {
            return Err(rejected());
        }
        let registration = registration_for_original_request(
            operation,
            &request,
            &context.budget().invocation_quotas,
            &self.revocation_authority_domain,
        )?;
        // The client authenticates the configured Unix peer and validates the
        // acknowledgement against the original operation and attempt identities.
        self.client.register_attempt(&registration, &request)?;
        Ok(())
    }
}

pub(super) fn registration_for_original_request(
    operation: &AdmissionOperationBindingV1,
    request: &BrokerExecuteRequest,
    quotas: &[BudgetInvocationQuota],
    revocation_authority_domain: &str,
) -> Result<AttemptRegistration> {
    let request_digest = broker_request_digest(request)?;
    let registration = AttemptRegistration {
        ids: derive_attempt_ids_for_operation(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
            operation.operation_id().as_str(),
        )?,
        invocation_id: request.invocation_id.clone(),
        parent_capability_id: request.capability.body.parent_capability_id.clone(),
        broker_capability_id: request.capability.body.capability_id.clone(),
        request_digest,
        request_canonical_digest: broker_execute_request_registration_digest(request)?,
        proof_digest: crate::proof::proof_digest(&request.proof)?,
        proof_key_id: request.proof.body.authority_key.to_hex(),
        proof_nonce: request.proof.body.nonce.clone(),
        nonce_expires_at_unix_seconds: request
            .proof
            .body
            .issued_at_unix_seconds
            .checked_add(request.capability.body.proof.nonce_ttl_seconds)
            .ok_or_else(rejected)?,
        quotas: registration_quotas(quotas, request)?,
        authority_metadata_digest: operation.request_binding_hash().as_str().to_owned(),
        revocation_authority_domain: revocation_authority_domain.into(),
    };
    registration.validate()?;
    Ok(registration)
}

impl SupplementalAdmissionParticipant for BrokerAdmissionParticipant {
    fn requires_registration(&self, server_id: &str, tool_name: &str) -> bool {
        server_id == self.server_id && tool_name == self.tool_name
    }

    fn register_original(
        &self,
        context: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> std::result::Result<(), SupplementalQuotaVerifierError> {
        self.register(context)
            .map_err(|error| SupplementalQuotaVerifierError::new(error.diagnostic_code()))
    }
}

/// Broker-visible aliases of the kernel's composite quota participants. This
/// conversion does not create counters, authorize a hold or permit capture.
pub(crate) fn registration_quotas(
    quotas: &[BudgetInvocationQuota],
    request: &BrokerExecuteRequest,
) -> Result<Vec<ExecutionQuota>> {
    let mut broker_count = 0;
    let mut parent_count = 0;
    let mut projected = Vec::with_capacity(quotas.len());
    for quota in quotas {
        quota.key.validate().map_err(|_| rejected())?;
        let key_id = match quota.key.profile {
            BudgetQuotaProfile::SupplementalBrokerCapabilityExecution => {
                broker_count += 1;
                if quota.max_invocations != request.capability.body.maximum_executions {
                    return Err(rejected());
                }
                request.capability.body.broker_quota_key_id.clone()
            }
            profile => {
                if profile == BudgetQuotaProfile::GrantInvocation
                    && quota.key.owner_id == request.capability.body.parent_capability_id
                {
                    parent_count += 1;
                }
                let material = canonical(&serde_json::json!({
                    "schema": "chio.secret-broker.kernel-quota-alias.v1",
                    "profile": profile.as_str(),
                    "owner_id": quota.key.owner_id,
                    "grant_index": quota.key.grant_index,
                }))?;
                format!("kernel-quota-{}", hex::encode(Sha256::digest(material)))
            }
        };
        projected.push(ExecutionQuota {
            key_id,
            maximum_executions: quota.max_invocations,
        });
    }
    if broker_count != 1 || parent_count != 1 {
        return Err(rejected());
    }
    let canonical = canonicalize_quotas(projected)?;
    if canonical.len() != quotas.len() {
        return Err(rejected());
    }
    Ok(canonical)
}

struct RegistrationSigner {
    inner: Arc<dyn SigningBackend>,
    key: PublicKey,
}

impl SigningBackend for RegistrationSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.key.algorithm()
    }
    fn public_key(&self) -> PublicKey {
        self.key.clone()
    }
    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        self.sign_bytes_with_identity(message)
            .map(|signed| signed.signature)
    }
    fn sign_bytes_with_identity(&self, message: &[u8]) -> chio_core_types::Result<SigningOutcome> {
        self.inner.sign_bytes_for_identity(&self.key, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::{Ed25519Backend, Keypair};

    #[test]
    fn registered_generation_cannot_sign_with_a_rotated_authority_key() -> Result<()> {
        let original = Keypair::from_seed(&[34; 32]);
        let pinned = RegistrationSigner {
            inner: Arc::new(Ed25519Backend::new(original.clone())),
            key: original.public_key(),
        };
        let signed = pinned
            .sign_bytes_with_identity(b"original registration")
            .map_err(|_| rejected())?;
        assert_eq!(signed.public_key, original.public_key());
        let changed = RegistrationSigner {
            inner: Arc::new(Ed25519Backend::new(Keypair::from_seed(&[35; 32]))),
            key: original.public_key(),
        };
        assert!(changed
            .sign_bytes_with_identity(b"original registration")
            .is_err());
        Ok(())
    }
}
