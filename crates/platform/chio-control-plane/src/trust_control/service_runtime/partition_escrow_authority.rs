use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::{
    canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm,
};
use chio_kernel::budget_store::{
    BudgetStoreError, PartitionEscrowCommitEvidence, PartitionEscrowStoreBinding,
};
use chio_kernel::partition_escrow::{
    PartitionEscrowAdmissionEvidence, PartitionEscrowRegistry, PartitionEscrowRegistryInput,
};
use serde::{Deserialize, Serialize};

use crate::trust_control::service_types::ClusterMemberIdentity;
use crate::CliError;

pub const PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_SCHEMA: &str =
    "chio.partition-escrow-remote-authority.v1";
const PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_DOMAIN: &[u8] =
    b"chio.partition-escrow-remote-authority.v1\0";
const MAX_PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowRemoteAuthorityDescriptorBody {
    pub schema: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub service_endpoints: Vec<String>,
    pub cluster_members: Vec<ClusterMemberIdentity>,
    pub admission_membership_digest: String,
    pub registry: PartitionEscrowRegistryInput,
}

/// Operator-supplied first-generation authority material. The admission
/// membership digest is derived from the initialized HA consensus store during
/// provisioning and therefore cannot be supplied by the operator.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowRemoteAuthorityProvisioningInput {
    pub schema: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub service_endpoints: Vec<String>,
    pub cluster_members: Vec<ClusterMemberIdentity>,
    pub registry: PartitionEscrowRegistryInput,
}

impl PartitionEscrowRemoteAuthorityProvisioningInput {
    pub(crate) fn validate_current(&self, now: u64) -> Result<(), CliError> {
        let body = self.clone().into_descriptor_body("0".repeat(64));
        validate_descriptor_body(&body)?;
        validate_descriptor_freshness(&body, now)?;
        PartitionEscrowRegistry::new(body.registry)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "partition escrow remote authority registry is invalid: {error}"
                ))
            })?
            .validate_current(now)
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }

    pub(crate) fn into_descriptor_body(
        self,
        admission_membership_digest: String,
    ) -> PartitionEscrowRemoteAuthorityDescriptorBody {
        PartitionEscrowRemoteAuthorityDescriptorBody {
            schema: self.schema,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            service_endpoints: self.service_endpoints,
            cluster_members: self.cluster_members,
            admission_membership_digest,
            registry: self.registry,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPartitionEscrowRemoteAuthorityDescriptor {
    pub body: PartitionEscrowRemoteAuthorityDescriptorBody,
    pub signer_public_key: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl SignedPartitionEscrowRemoteAuthorityDescriptor {
    pub fn sign(
        body: PartitionEscrowRemoteAuthorityDescriptorBody,
        keypair: &Keypair,
    ) -> Result<Self, CliError> {
        validate_descriptor_body(&body)?;
        let signer_public_key = keypair.public_key();
        let algorithm = signer_public_key.algorithm();
        let signing_bytes = descriptor_signing_bytes(&body, &signer_public_key, algorithm)?;
        Ok(Self {
            body,
            signer_public_key,
            algorithm,
            signature: keypair.sign(&signing_bytes),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CliError> {
        canonical_json_bytes(self).map_err(|error| {
            CliError::cli_other_error(format!(
                "partition escrow remote authority descriptor cannot be canonicalized: {error}"
            ))
        })
    }

    fn verify_signature(&self, expected_signer: &PublicKey) -> Result<(), CliError> {
        if &self.signer_public_key != expected_signer
            || self.algorithm != self.signer_public_key.algorithm()
            || self.algorithm != self.signature.algorithm()
        {
            return Err(CliError::cli_other_error(
                "partition escrow remote authority descriptor signer does not match its pinned trust root"
                    .to_string(),
            ));
        }
        let signing_bytes =
            descriptor_signing_bytes(&self.body, &self.signer_public_key, self.algorithm)?;
        if !self
            .signer_public_key
            .verify(&signing_bytes, &self.signature)
        {
            return Err(CliError::cli_other_error(
                "partition escrow remote authority descriptor signature is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SealedPartitionEscrowRemoteAuthority {
    descriptor: SignedPartitionEscrowRemoteAuthorityDescriptor,
    descriptor_digest: String,
    trusted_descriptor_signer: PublicKey,
    registry: Arc<PartitionEscrowRegistry>,
    store_binding: PartitionEscrowStoreBinding,
}

impl SealedPartitionEscrowRemoteAuthority {
    pub fn from_canonical_descriptor(
        canonical_descriptor: &[u8],
        trusted_descriptor_signer: &PublicKey,
        now: u64,
    ) -> Result<Self, CliError> {
        if canonical_descriptor.is_empty()
            || canonical_descriptor.len() > MAX_PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_BYTES
        {
            return Err(CliError::cli_other_error(
                "partition escrow remote authority descriptor is empty or exceeds its byte limit"
                    .to_string(),
            ));
        }
        let descriptor: SignedPartitionEscrowRemoteAuthorityDescriptor =
            serde_json::from_slice(canonical_descriptor).map_err(|error| {
                CliError::cli_other_error(format!(
                    "partition escrow remote authority descriptor is invalid: {error}"
                ))
            })?;
        if descriptor.canonical_bytes()?.as_slice() != canonical_descriptor {
            return Err(CliError::cli_other_error(
                "partition escrow remote authority descriptor is not canonical JSON".to_string(),
            ));
        }
        validate_descriptor_body(&descriptor.body)?;
        descriptor.verify_signature(trusted_descriptor_signer)?;
        validate_descriptor_freshness(&descriptor.body, now)?;
        let registry = Arc::new(
            PartitionEscrowRegistry::new(descriptor.body.registry.clone()).map_err(|error| {
                CliError::cli_other_error(format!(
                    "partition escrow remote authority registry is invalid: {error}"
                ))
            })?,
        );
        let durable = registry.durable_store();
        let store_binding = PartitionEscrowStoreBinding::new(
            durable.store_identity_digest().to_string(),
            durable.counter_namespace_digest().to_string(),
            durable.fencing_token(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let descriptor_digest = sha256_hex(canonical_descriptor);
        Ok(Self {
            descriptor,
            descriptor_digest,
            trusted_descriptor_signer: trusted_descriptor_signer.clone(),
            registry,
            store_binding,
        })
    }

    pub fn verify_current(&self, now: u64) -> Result<(), BudgetStoreError> {
        self.verify_sealed_configuration()
            .and_then(|_| validate_descriptor_freshness(&self.descriptor.body, now))
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        self.registry
            .validate_current(now)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))
    }

    pub fn verify_current_now(&self) -> Result<(), BudgetStoreError> {
        self.verify_current(partition_escrow_unix_time_now()?)
    }

    pub fn verify_persisted_configuration(&self) -> Result<(), BudgetStoreError> {
        self.verify_sealed_configuration()
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))
    }

    pub fn validate_fresh_authorization_evidence(
        &self,
        evidence: &PartitionEscrowCommitEvidence,
        now: u64,
    ) -> Result<(), BudgetStoreError> {
        self.verify_current(now)?;
        self.validate_persisted_commit_evidence(evidence)?;
        validate_evidence_freshness(&evidence.evidence()?, now)
    }

    pub fn validate_persisted_commit_evidence(
        &self,
        evidence: &PartitionEscrowCommitEvidence,
    ) -> Result<(), BudgetStoreError> {
        self.verify_sealed_configuration()
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        evidence.validate_store_binding(&self.store_binding)?;
        let persisted = evidence.evidence()?;
        self.registry
            .verify_persisted_admission(&persisted)
            .map_err(|error| {
                BudgetStoreError::Conflict(format!(
                    "partition escrow proof does not match the sealed remote authority: {error}"
                ))
            })
    }

    pub fn validate_fresh_authorization_evidence_now(
        &self,
        evidence: &PartitionEscrowCommitEvidence,
    ) -> Result<(), BudgetStoreError> {
        self.validate_fresh_authorization_evidence(evidence, partition_escrow_unix_time_now()?)
    }

    pub fn validate_service_endpoints(&self, endpoints: &[String]) -> Result<(), CliError> {
        if self.descriptor.body.service_endpoints != endpoints {
            return Err(CliError::cli_other_error(
                "partition escrow remote authority endpoints do not match the signed descriptor"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_cluster_members(
        &self,
        members: &[ClusterMemberIdentity],
    ) -> Result<(), CliError> {
        if !same_cluster_members(&self.descriptor.body.cluster_members, members) {
            return Err(CliError::cli_other_error(
                "partition escrow cluster membership does not match the signed descriptor"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn registry(&self) -> &Arc<PartitionEscrowRegistry> {
        &self.registry
    }

    pub fn store_binding(&self) -> &PartitionEscrowStoreBinding {
        &self.store_binding
    }

    pub fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub fn admission_membership_digest(&self) -> &str {
        &self.descriptor.body.admission_membership_digest
    }

    pub(crate) fn service_endpoints(&self) -> &[String] {
        &self.descriptor.body.service_endpoints
    }

    pub(crate) fn member_public_key(&self, node_id: &str) -> Option<&PublicKey> {
        self.descriptor
            .body
            .cluster_members
            .iter()
            .find(|member| member.node_url == node_id)
            .map(|member| &member.public_key)
    }

    fn verify_sealed_configuration(&self) -> Result<(), CliError> {
        validate_descriptor_body(&self.descriptor.body)?;
        self.descriptor
            .verify_signature(&self.trusted_descriptor_signer)
    }
}

fn partition_escrow_unix_time_now() -> Result<u64, BudgetStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "system clock is before the Unix epoch while validating partition escrow: {error}"
            ))
        })
}

fn validate_descriptor_body(
    body: &PartitionEscrowRemoteAuthorityDescriptorBody,
) -> Result<(), CliError> {
    if body.schema != PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_SCHEMA {
        return Err(CliError::cli_other_error(
            "partition escrow remote authority descriptor schema is unsupported".to_string(),
        ));
    }
    if body.issued_at >= body.expires_at {
        return Err(CliError::cli_other_error(
            "partition escrow remote authority descriptor validity window is invalid".to_string(),
        ));
    }
    if !is_lower_sha256(&body.admission_membership_digest) {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor admission membership digest is invalid".to_string(),
        ));
    }
    if body.service_endpoints.is_empty() || body.cluster_members.is_empty() {
        return Err(CliError::cli_other_error(
            "partition escrow remote authority descriptor requires endpoints and cluster members"
                .to_string(),
        ));
    }
    validate_strictly_sorted_identifiers(&body.service_endpoints, "service endpoints")?;
    let member_urls = body
        .cluster_members
        .iter()
        .map(|member| member.node_url.clone())
        .collect::<Vec<_>>();
    validate_strictly_sorted_identifiers(&member_urls, "cluster member URLs")?;
    if member_urls != body.service_endpoints {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor endpoints must exactly equal its cluster member URLs"
                .to_string(),
        ));
    }
    let unique_keys = body
        .cluster_members
        .iter()
        .map(|member| member.public_key.to_hex())
        .collect::<BTreeSet<_>>();
    if unique_keys.len() != body.cluster_members.len() {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor cluster member keys must be unique".to_string(),
        ));
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_descriptor_freshness(
    body: &PartitionEscrowRemoteAuthorityDescriptorBody,
    now: u64,
) -> Result<(), CliError> {
    if now < body.issued_at || now >= body.expires_at {
        return Err(CliError::cli_other_error(
            "partition escrow remote authority descriptor is not currently valid".to_string(),
        ));
    }
    Ok(())
}

fn validate_evidence_freshness(
    evidence: &PartitionEscrowAdmissionEvidence,
    now: u64,
) -> Result<(), BudgetStoreError> {
    if evidence.verified_at() > now
        || evidence
            .quotas()
            .iter()
            .any(|quota| now < quota.source_not_before() || now >= quota.source_expires_at())
    {
        return Err(BudgetStoreError::Conflict(
            "partition escrow proof is not valid at the current mutation time".to_string(),
        ));
    }
    Ok(())
}

fn validate_strictly_sorted_identifiers(values: &[String], label: &str) -> Result<(), CliError> {
    if values.iter().any(|value| {
        value.is_empty()
            || value.len() > 2048
            || value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
    }) || values
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(CliError::cli_other_error(format!(
            "partition escrow descriptor {label} must be nonempty, bounded, and strictly sorted"
        )));
    }
    Ok(())
}

fn same_cluster_members(left: &[ClusterMemberIdentity], right: &[ClusterMemberIdentity]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.node_url == right.node_url && left.public_key == right.public_key
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PartitionEscrowRemoteAuthoritySigningPayload<'a> {
    domain: &'static str,
    body: &'a PartitionEscrowRemoteAuthorityDescriptorBody,
    signer_public_key: &'a PublicKey,
    algorithm: SigningAlgorithm,
}

fn descriptor_signing_bytes(
    body: &PartitionEscrowRemoteAuthorityDescriptorBody,
    signer_public_key: &PublicKey,
    algorithm: SigningAlgorithm,
) -> Result<Vec<u8>, CliError> {
    let payload = PartitionEscrowRemoteAuthoritySigningPayload {
        domain: PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|error| {
        CliError::cli_other_error(format!(
            "partition escrow remote authority signing payload cannot be canonicalized: {error}"
        ))
    })?;
    let mut signing_bytes = Vec::with_capacity(
        PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_DOMAIN.len() + canonical.len(),
    );
    signing_bytes.extend_from_slice(PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_DOMAIN);
    signing_bytes.extend_from_slice(&canonical);
    Ok(signing_bytes)
}
