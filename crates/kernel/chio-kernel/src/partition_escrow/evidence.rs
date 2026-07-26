use chio_core_types::partition_escrow::{
    PartitionEscrowQuota, SignedPartitionEscrowAllocationSet, SignedPartitionEscrowQuotaCommitment,
};
use chio_core_types::{canonical_json_bytes, sha256_hex, PublicKey};
use serde::{Deserialize, Serialize};

use super::error::PartitionEscrowRegistryError;
use super::source::PartitionEscrowSourceTrustEvidence;
use crate::budget_store::{
    MAX_INVOCATION_QUOTAS_PER_ADMISSION, MAX_PARTITION_ESCROW_ADMISSION_EVIDENCE_BYTES,
};

pub const PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA: &str =
    "chio.partition-escrow-admission-evidence.v1";
const PARTITION_ESCROW_ADMISSION_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"chio.partition-escrow-admission-evidence.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowResolverRuntimeEvidence {
    pub(super) resolver_id: String,
    pub(super) implementation_id: String,
    pub(super) implementation_version: u32,
    pub(super) configuration_digest: String,
}

impl PartitionEscrowResolverRuntimeEvidence {
    pub fn resolver_id(&self) -> &str {
        &self.resolver_id
    }

    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    pub const fn implementation_version(&self) -> u32 {
        self.implementation_version
    }

    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowDurableStoreEvidence {
    pub(super) store_identity_digest: String,
    pub(super) counter_namespace_digest: String,
    pub(super) fencing_token: u64,
}

impl PartitionEscrowDurableStoreEvidence {
    pub fn store_identity_digest(&self) -> &str {
        &self.store_identity_digest
    }

    pub fn counter_namespace_digest(&self) -> &str {
        &self.counter_namespace_digest
    }

    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowAdmissionQuotaEvidence {
    pub(super) global_quota: PartitionEscrowQuota,
    pub(super) local_allocated_invocations: u32,
    pub(super) quota_key_digest: String,
    pub(super) quota_descriptor_digest: String,
    pub(super) quota_certificate_binding_digest: String,
    pub(super) quota_commitment_digest: String,
    pub(super) underlying_source_artifact_digest: String,
    pub(super) source_trust_binding_digest: String,
    pub(super) source_not_before: u64,
    pub(super) source_expires_at: u64,
    pub(super) source_signer: PublicKey,
    pub(super) source_trust: PartitionEscrowSourceTrustEvidence,
    pub(super) allocation_plan_digest: String,
    pub(super) allocation_root_id: String,
    pub(super) allocation_epoch: u64,
    pub(super) allocation_set_digest: String,
    pub(super) total_allocated_invocations: u64,
    pub(super) quota_commitment: SignedPartitionEscrowQuotaCommitment,
    pub(super) allocation_set: SignedPartitionEscrowAllocationSet,
}

impl PartitionEscrowAdmissionQuotaEvidence {
    pub const fn global_quota(&self) -> &PartitionEscrowQuota {
        &self.global_quota
    }

    pub const fn local_allocated_invocations(&self) -> u32 {
        self.local_allocated_invocations
    }

    pub fn quota_key_digest(&self) -> &str {
        &self.quota_key_digest
    }

    pub fn quota_descriptor_digest(&self) -> &str {
        &self.quota_descriptor_digest
    }

    pub fn quota_certificate_binding_digest(&self) -> &str {
        &self.quota_certificate_binding_digest
    }

    pub fn quota_commitment_digest(&self) -> &str {
        &self.quota_commitment_digest
    }

    pub fn underlying_source_artifact_digest(&self) -> &str {
        &self.underlying_source_artifact_digest
    }

    pub fn source_trust_binding_digest(&self) -> &str {
        &self.source_trust_binding_digest
    }

    pub const fn source_not_before(&self) -> u64 {
        self.source_not_before
    }

    pub const fn source_expires_at(&self) -> u64 {
        self.source_expires_at
    }

    pub const fn source_signer(&self) -> &PublicKey {
        &self.source_signer
    }

    pub fn allocation_plan_digest(&self) -> &str {
        &self.allocation_plan_digest
    }

    pub fn allocation_root_id(&self) -> &str {
        &self.allocation_root_id
    }

    pub const fn allocation_epoch(&self) -> u64 {
        self.allocation_epoch
    }

    pub fn allocation_set_digest(&self) -> &str {
        &self.allocation_set_digest
    }

    pub const fn total_allocated_invocations(&self) -> u64 {
        self.total_allocated_invocations
    }

    pub const fn quota_commitment(&self) -> &SignedPartitionEscrowQuotaCommitment {
        &self.quota_commitment
    }

    pub const fn allocation_set(&self) -> &SignedPartitionEscrowAllocationSet {
        &self.allocation_set
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowAdmissionEvidence {
    pub(super) schema: String,
    pub(super) verified_at: u64,
    pub(super) resolver: PartitionEscrowResolverRuntimeEvidence,
    pub(super) durable_store: PartitionEscrowDurableStoreEvidence,
    pub(super) authority_domain: String,
    pub(super) partition_id: String,
    pub(super) authority_id: String,
    pub(super) quotas: Vec<PartitionEscrowAdmissionQuotaEvidence>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowAdmissionEvidenceWire {
    schema: String,
    verified_at: u64,
    resolver: PartitionEscrowResolverRuntimeEvidence,
    durable_store: PartitionEscrowDurableStoreEvidence,
    authority_domain: String,
    partition_id: String,
    authority_id: String,
    quotas: Vec<PartitionEscrowAdmissionQuotaEvidenceWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowAdmissionQuotaEvidenceWire {
    global_quota: PartitionEscrowQuota,
    local_allocated_invocations: u32,
    quota_key_digest: String,
    quota_descriptor_digest: String,
    quota_certificate_binding_digest: String,
    quota_commitment_digest: String,
    underlying_source_artifact_digest: String,
    source_trust_binding_digest: String,
    source_not_before: u64,
    source_expires_at: u64,
    source_signer: PublicKey,
    source_trust: PartitionEscrowSourceTrustEvidence,
    allocation_plan_digest: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    allocation_set_digest: String,
    total_allocated_invocations: u64,
    quota_commitment: serde_json::Value,
    allocation_set: serde_json::Value,
}

impl PartitionEscrowAdmissionEvidence {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub const fn verified_at(&self) -> u64 {
        self.verified_at
    }

    pub const fn resolver(&self) -> &PartitionEscrowResolverRuntimeEvidence {
        &self.resolver
    }

    pub const fn durable_store(&self) -> &PartitionEscrowDurableStoreEvidence {
        &self.durable_store
    }

    pub fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn quotas(&self) -> &[PartitionEscrowAdmissionQuotaEvidence] {
        &self.quotas
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PartitionEscrowRegistryError> {
        canonical_json_bytes(self)
            .map_err(|error| PartitionEscrowRegistryError::Canonicalization(error.to_string()))
    }

    pub fn digest(&self) -> Result<String, PartitionEscrowRegistryError> {
        let canonical = self.canonical_bytes()?;
        let mut input = Vec::with_capacity(
            PARTITION_ESCROW_ADMISSION_EVIDENCE_DIGEST_DOMAIN.len() + canonical.len(),
        );
        input.extend_from_slice(PARTITION_ESCROW_ADMISSION_EVIDENCE_DIGEST_DOMAIN);
        input.extend_from_slice(&canonical);
        Ok(sha256_hex(&input))
    }

    pub fn from_canonical_json_bytes(bytes: &[u8]) -> Result<Self, PartitionEscrowRegistryError> {
        if bytes.is_empty() || bytes.len() > MAX_PARTITION_ESCROW_ADMISSION_EVIDENCE_BYTES {
            return Err(PartitionEscrowRegistryError::InvalidEvidenceEnvelope(
                "evidence is empty or exceeds its byte limit".to_string(),
            ));
        }
        let wire: PartitionEscrowAdmissionEvidenceWire =
            serde_json::from_slice(bytes).map_err(|error| {
                PartitionEscrowRegistryError::InvalidEvidenceEnvelope(error.to_string())
            })?;
        if wire.quotas.is_empty() || wire.quotas.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
            return Err(PartitionEscrowRegistryError::InvalidAdmissionQuotaCount);
        }
        let mut quotas = Vec::with_capacity(wire.quotas.len());
        for quota in wire.quotas {
            let commitment_bytes =
                canonical_json_bytes(&quota.quota_commitment).map_err(|error| {
                    PartitionEscrowRegistryError::Canonicalization(error.to_string())
                })?;
            let allocation_bytes =
                canonical_json_bytes(&quota.allocation_set).map_err(|error| {
                    PartitionEscrowRegistryError::Canonicalization(error.to_string())
                })?;
            quotas.push(PartitionEscrowAdmissionQuotaEvidence {
                global_quota: quota.global_quota,
                local_allocated_invocations: quota.local_allocated_invocations,
                quota_key_digest: quota.quota_key_digest,
                quota_descriptor_digest: quota.quota_descriptor_digest,
                quota_certificate_binding_digest: quota.quota_certificate_binding_digest,
                quota_commitment_digest: quota.quota_commitment_digest,
                underlying_source_artifact_digest: quota.underlying_source_artifact_digest,
                source_trust_binding_digest: quota.source_trust_binding_digest,
                source_not_before: quota.source_not_before,
                source_expires_at: quota.source_expires_at,
                source_signer: quota.source_signer,
                source_trust: quota.source_trust,
                allocation_plan_digest: quota.allocation_plan_digest,
                allocation_root_id: quota.allocation_root_id,
                allocation_epoch: quota.allocation_epoch,
                allocation_set_digest: quota.allocation_set_digest,
                total_allocated_invocations: quota.total_allocated_invocations,
                quota_commitment: SignedPartitionEscrowQuotaCommitment::from_canonical_json_bytes(
                    &commitment_bytes,
                )?,
                allocation_set: SignedPartitionEscrowAllocationSet::from_canonical_json_bytes(
                    &allocation_bytes,
                )?,
            });
        }
        let evidence = Self {
            schema: wire.schema,
            verified_at: wire.verified_at,
            resolver: wire.resolver,
            durable_store: wire.durable_store,
            authority_domain: wire.authority_domain,
            partition_id: wire.partition_id,
            authority_id: wire.authority_id,
            quotas,
        };
        if evidence.canonical_bytes()?.as_slice() != bytes {
            return Err(PartitionEscrowRegistryError::NonCanonicalEvidenceEnvelope);
        }
        Ok(evidence)
    }
}
