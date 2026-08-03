use std::collections::{BTreeMap, BTreeSet};

use chio_core::capability::aggregate_budget::VerifiedAggregateInvocationAuthority;
use chio_core::capability::token::CapabilityToken;
use chio_core_types::partition_escrow::{
    verify_partition_escrow_allocation_set, verify_partition_escrow_allocation_set_structure,
    verify_partition_escrow_quota_commitment, PartitionEscrowAllocationVerificationContext,
    PartitionEscrowQuota, SignedPartitionEscrowAllocationSet, SignedPartitionEscrowQuotaCommitment,
    VerifiedPartitionEscrowQuotaCertificate,
};
use chio_core_types::{canonical_json_bytes, sha256_hex, PublicKey};
use serde::{Deserialize, Serialize};

use super::error::PartitionEscrowRegistryError;
use super::evidence::{
    PartitionEscrowAdmissionEvidence, PartitionEscrowAdmissionQuotaEvidence,
    PartitionEscrowDurableStoreEvidence, PartitionEscrowResolverRuntimeEvidence,
    PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA,
};
use super::source::{
    source_trust_binding_digest, source_trust_matches_quota,
    verify_aggregate_capability_partition_escrow_source,
    verify_aggregate_family_partition_escrow_source, verify_broker_partition_escrow_source,
    verify_grant_partition_escrow_source, VerifiedPartitionEscrowQuotaSource,
};
use crate::budget_store::{
    BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile, VerifiedInvocationAdmission,
    MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};
use crate::supplemental_quota::VerifiedSupplementalQuota;

pub const PARTITION_ESCROW_REGISTRY_SCHEMA: &str = "chio.partition-escrow-registry.v1";
const PARTITION_ESCROW_REGISTRY_DIGEST_DOMAIN: &[u8] = b"chio.partition-escrow-registry.v1\0";
const PARTITION_ESCROW_COUNTER_NAMESPACE_DIGEST_DOMAIN: &[u8] =
    b"chio.partition-escrow-counter-namespace.v1\0";
const MAX_REGISTRY_IDENTIFIER_BYTES: usize = 512;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowRegistryEntryInput {
    pub quota_commitment: SignedPartitionEscrowQuotaCommitment,
    pub allocation_set: SignedPartitionEscrowAllocationSet,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowRegistryEntryInputWire {
    quota_commitment: serde_json::Value,
    allocation_set: serde_json::Value,
}

impl<'de> Deserialize<'de> for PartitionEscrowRegistryEntryInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PartitionEscrowRegistryEntryInputWire::deserialize(deserializer)?;
        let commitment = canonical_json_bytes(&wire.quota_commitment)
            .map_err(serde::de::Error::custom)
            .and_then(|bytes| {
                SignedPartitionEscrowQuotaCommitment::from_canonical_json_bytes(&bytes)
                    .map_err(serde::de::Error::custom)
            })?;
        let allocation_set = canonical_json_bytes(&wire.allocation_set)
            .map_err(serde::de::Error::custom)
            .and_then(|bytes| {
                SignedPartitionEscrowAllocationSet::from_canonical_json_bytes(&bytes)
                    .map_err(serde::de::Error::custom)
            })?;
        Ok(Self {
            quota_commitment: commitment,
            allocation_set,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowRegistryInput {
    pub authority_domain: String,
    pub partition_id: String,
    pub authority_id: String,
    pub resolver_id: String,
    pub resolver_implementation_id: String,
    pub resolver_implementation_version: u32,
    pub store_identity_digest: String,
    pub counter_namespace_digest: String,
    pub fencing_token: u64,
    pub entries: Vec<PartitionEscrowRegistryEntryInput>,
}

#[derive(Clone, Debug)]
struct PinnedAllocationSet {
    load_certificate: VerifiedPartitionEscrowQuotaCertificate,
    quota_key_digest: String,
    quota_descriptor_digest: String,
    quota_certificate_binding_digest: String,
    quota_commitment_digest: String,
    allocation_set_digest: String,
    quota_commitment: SignedPartitionEscrowQuotaCommitment,
    allocation_set: SignedPartitionEscrowAllocationSet,
}

/// Sealed quota produced only after live source binding and exact registry
/// resolution. Its enforceable maximum is the local signed allocation, not the
/// source's global maximum.
#[derive(Clone, Debug)]
pub struct AdmissionCapableEscrowQuota {
    global_quota: BudgetInvocationQuota,
    local_quota: BudgetInvocationQuota,
    evidence: PartitionEscrowAdmissionQuotaEvidence,
}

impl AdmissionCapableEscrowQuota {
    pub fn global_quota(&self) -> &BudgetInvocationQuota {
        &self.global_quota
    }

    pub fn local_quota(&self) -> &BudgetInvocationQuota {
        &self.local_quota
    }

    pub const fn evidence(&self) -> &PartitionEscrowAdmissionQuotaEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug)]
pub struct PartitionEscrowAdmission {
    quotas: Vec<AdmissionCapableEscrowQuota>,
    evidence: PartitionEscrowAdmissionEvidence,
    evidence_digest: String,
}

impl PartitionEscrowAdmission {
    pub fn quotas(&self) -> &[AdmissionCapableEscrowQuota] {
        &self.quotas
    }

    pub const fn evidence(&self) -> &PartitionEscrowAdmissionEvidence {
        &self.evidence
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug)]
pub struct PartitionEscrowRegistry {
    authority_domain: String,
    partition_id: String,
    authority_id: String,
    runtime_evidence: PartitionEscrowResolverRuntimeEvidence,
    durable_store: PartitionEscrowDurableStoreEvidence,
    allocation_sets: BTreeMap<String, PinnedAllocationSet>,
}

impl PartitionEscrowRegistry {
    pub fn new(input: PartitionEscrowRegistryInput) -> Result<Self, PartitionEscrowRegistryError> {
        validate_registry_input(&input)?;
        let mut allocation_sets = BTreeMap::new();
        let mut certificate_bindings = BTreeSet::new();
        for entry in &input.entries {
            let load_time = entry.quota_commitment.body().source_not_before();
            let certificate =
                verify_partition_escrow_quota_commitment(&entry.quota_commitment, load_time)?;
            if certificate.authority_domain() != input.authority_domain {
                return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
                    "registry authority domain",
                ));
            }
            if certificate.allocation_epoch() != input.fencing_token {
                return Err(PartitionEscrowRegistryError::DurableStoreBindingMismatch);
            }
            let verification_context = PartitionEscrowAllocationVerificationContext::new(
                input.partition_id.as_str(),
                input.authority_id.as_str(),
                &certificate,
            )?;
            let verified = verify_partition_escrow_allocation_set_structure(
                &entry.allocation_set,
                &verification_context,
                None,
            )?;
            let quota_key_digest = certificate.quota().key_digest()?;
            let quota_descriptor_digest = certificate.quota().descriptor_digest()?;
            let quota_certificate_binding_digest = certificate.binding_digest()?;
            let quota_commitment_digest = certificate.commitment_digest().to_string();
            if verified.quota_certificate_binding_digest()
                != quota_certificate_binding_digest.as_str()
                || verified.quota_commitment_digest() != quota_commitment_digest
            {
                return Err(PartitionEscrowRegistryError::MissingAllocationSet);
            }
            if !certificate_bindings.insert(quota_certificate_binding_digest.clone()) {
                return Err(PartitionEscrowRegistryError::EquivocatingAllocationSet);
            }
            let pin = PinnedAllocationSet {
                load_certificate: certificate,
                quota_key_digest: quota_key_digest.clone(),
                quota_descriptor_digest,
                quota_certificate_binding_digest,
                quota_commitment_digest,
                allocation_set_digest: verified.allocation_set_digest().to_string(),
                quota_commitment: entry.quota_commitment.clone(),
                allocation_set: entry.allocation_set.clone(),
            };
            if allocation_sets.insert(quota_key_digest, pin).is_some() {
                return Err(PartitionEscrowRegistryError::EquivocatingAllocationSet);
            }
        }

        let durable_store = PartitionEscrowDurableStoreEvidence {
            store_identity_digest: input.store_identity_digest.clone(),
            counter_namespace_digest: input.counter_namespace_digest.clone(),
            fencing_token: input.fencing_token,
        };
        let configuration_digest =
            registry_configuration_digest(&input, &durable_store, &allocation_sets)?;
        let runtime_evidence = PartitionEscrowResolverRuntimeEvidence {
            resolver_id: input.resolver_id,
            implementation_id: input.resolver_implementation_id,
            implementation_version: input.resolver_implementation_version,
            configuration_digest,
        };
        validate_runtime_evidence(&runtime_evidence)?;
        Ok(Self {
            authority_domain: input.authority_domain,
            partition_id: input.partition_id,
            authority_id: input.authority_id,
            runtime_evidence,
            durable_store,
            allocation_sets,
        })
    }

    pub const fn runtime_evidence(&self) -> &PartitionEscrowResolverRuntimeEvidence {
        &self.runtime_evidence
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

    pub fn allocation_set_count(&self) -> usize {
        self.allocation_sets.len()
    }

    /// Revalidate every sealed quota and allocation against the current time.
    ///
    /// Registry construction proves immutable structure. A production startup
    /// must additionally prove that none of the embedded source or allocation
    /// windows has expired before the registry can authorize fresh work.
    pub fn validate_current(&self, now: u64) -> Result<(), PartitionEscrowRegistryError> {
        for pinned in self.allocation_sets.values() {
            let certificate =
                verify_partition_escrow_quota_commitment(&pinned.quota_commitment, now)?;
            let verification_context = PartitionEscrowAllocationVerificationContext::new(
                &self.partition_id,
                &self.authority_id,
                &certificate,
            )?;
            let verified = verify_partition_escrow_allocation_set(
                &pinned.allocation_set,
                &verification_context,
                now,
                Some(&pinned.allocation_set_digest),
            )?;
            if certificate.binding_digest()? != pinned.quota_certificate_binding_digest.as_str()
                || certificate.commitment_digest() != pinned.quota_commitment_digest.as_str()
                || verified.quota_certificate_binding_digest()
                    != pinned.quota_certificate_binding_digest.as_str()
                || verified.quota_commitment_digest() != pinned.quota_commitment_digest.as_str()
            {
                return Err(PartitionEscrowRegistryError::MissingAllocationSet);
            }
        }
        Ok(())
    }

    pub(crate) fn install_verified_admission(
        &self,
        capability: &CapabilityToken,
        grant_index: usize,
        aggregate: Option<&VerifiedAggregateInvocationAuthority>,
        supplemental: Option<&VerifiedSupplementalQuota>,
        admission: VerifiedInvocationAdmission,
        now: u64,
    ) -> Result<VerifiedInvocationAdmission, PartitionEscrowRegistryError> {
        let mut sources = Vec::with_capacity(admission.quotas().len());
        for quota in admission.quotas() {
            let partition_quota = PartitionEscrowQuota::new(
                quota.key().profile().as_str(),
                quota.key().owner_id(),
                quota.key().grant_index(),
                quota.max_invocations(),
            )?;
            let quota_key_digest = partition_quota.key_digest()?;
            let commitment = &self
                .allocation_sets
                .get(&quota_key_digest)
                .ok_or(PartitionEscrowRegistryError::MissingAllocationSet)?
                .quota_commitment;
            let source = match quota.key().profile() {
                BudgetQuotaProfile::GrantInvocation => verify_grant_partition_escrow_source(
                    commitment,
                    capability,
                    &admission,
                    grant_index,
                    now,
                )?,
                BudgetQuotaProfile::AggregateCapabilityInvocation => {
                    verify_aggregate_capability_partition_escrow_source(
                        commitment,
                        capability,
                        aggregate.ok_or(PartitionEscrowRegistryError::SourceBindingMismatch(
                            "aggregate capability authority",
                        ))?,
                        &admission,
                        now,
                    )?
                }
                BudgetQuotaProfile::AggregateFamilyInvocation => {
                    verify_aggregate_family_partition_escrow_source(
                        commitment,
                        aggregate.ok_or(PartitionEscrowRegistryError::SourceBindingMismatch(
                            "aggregate family authority",
                        ))?,
                        &admission,
                        now,
                    )?
                }
                BudgetQuotaProfile::SupplementalBrokerExecution => {
                    verify_broker_partition_escrow_source(
                        commitment,
                        supplemental.ok_or(PartitionEscrowRegistryError::SourceBindingMismatch(
                            "supplemental broker authority",
                        ))?,
                        &admission,
                        now,
                    )?
                }
            };
            sources.push(source);
        }
        let escrow = self.resolve(&sources, now)?;
        admission
            .install_partition_escrow(&escrow)
            .map_err(Into::into)
    }

    pub(crate) fn resolve(
        &self,
        ordered_sources: &[VerifiedPartitionEscrowQuotaSource],
        now: u64,
    ) -> Result<PartitionEscrowAdmission, PartitionEscrowRegistryError> {
        validate_ordered_sources(ordered_sources, now)?;
        let mut quotas = Vec::with_capacity(ordered_sources.len());
        for source in ordered_sources {
            quotas.push(self.resolve_quota(source, now)?);
        }
        let evidence = PartitionEscrowAdmissionEvidence {
            schema: PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA.to_string(),
            verified_at: now,
            resolver: self.runtime_evidence.clone(),
            durable_store: self.durable_store.clone(),
            authority_domain: self.authority_domain.clone(),
            partition_id: self.partition_id.clone(),
            authority_id: self.authority_id.clone(),
            quotas: quotas.iter().map(|quota| quota.evidence.clone()).collect(),
        };
        self.verify_persisted_admission(&evidence)?;
        let evidence_digest = evidence.digest()?;
        Ok(PartitionEscrowAdmission {
            quotas,
            evidence,
            evidence_digest,
        })
    }

    pub fn verify_persisted_admission(
        &self,
        evidence: &PartitionEscrowAdmissionEvidence,
    ) -> Result<(), PartitionEscrowRegistryError> {
        self.verify_evidence_identity(evidence)?;
        for quota in &evidence.quotas {
            self.verify_persisted_quota(quota, evidence.verified_at)?;
        }
        Ok(())
    }

    fn resolve_quota(
        &self,
        source: &VerifiedPartitionEscrowQuotaSource,
        now: u64,
    ) -> Result<AdmissionCapableEscrowQuota, PartitionEscrowRegistryError> {
        let certificate = source.certificate();
        let quota_key_digest = source.quota().key_digest()?;
        let quota_descriptor_digest = source.quota().descriptor_digest()?;
        let certificate_binding_digest = certificate.binding_digest()?;
        let pinned = self
            .allocation_sets
            .get(&quota_key_digest)
            .ok_or(PartitionEscrowRegistryError::MissingAllocationSet)?;
        if pinned.quota_key_digest != quota_key_digest
            || pinned.quota_descriptor_digest != quota_descriptor_digest
            || pinned.quota_certificate_binding_digest != certificate_binding_digest
            || pinned.quota_commitment_digest != certificate.commitment_digest()
            || &pinned.quota_commitment != source.quota_commitment()
        {
            return Err(PartitionEscrowRegistryError::MissingAllocationSet);
        }
        certificate.verify_commitment(&pinned.quota_commitment)?;
        let verification_context = PartitionEscrowAllocationVerificationContext::new(
            &self.partition_id,
            &self.authority_id,
            certificate,
        )?;
        let verified = verify_partition_escrow_allocation_set(
            &pinned.allocation_set,
            &verification_context,
            now,
            Some(&pinned.allocation_set_digest),
        )?;
        let local_quota = BudgetInvocationQuota::from_verified_parts(
            BudgetQuotaKey::from_verified_parts(
                source.global_quota().key().profile(),
                source.global_quota().key().owner_id().to_string(),
                source.global_quota().key().grant_index(),
            )?,
            verified.local_allocated_invocations(),
        )?;
        if local_quota.max_invocations() > source.global_quota().max_invocations() {
            return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
                "local allocation maximum",
            ));
        }
        let evidence = PartitionEscrowAdmissionQuotaEvidence {
            global_quota: source.quota().clone(),
            local_allocated_invocations: verified.local_allocated_invocations(),
            quota_key_digest,
            quota_descriptor_digest,
            quota_certificate_binding_digest: certificate_binding_digest,
            quota_commitment_digest: certificate.commitment_digest().to_string(),
            underlying_source_artifact_digest: certificate
                .underlying_source_artifact_digest()
                .to_string(),
            source_trust_binding_digest: certificate.source_trust_binding_digest().to_string(),
            source_not_before: certificate.source_not_before(),
            source_expires_at: certificate.source_expires_at(),
            source_signer: certificate.certificate_signer().clone(),
            source_trust: source.trust_evidence().clone(),
            allocation_plan_digest: certificate.allocation_plan_digest().to_string(),
            allocation_root_id: certificate.allocation_root_id().to_string(),
            allocation_epoch: certificate.allocation_epoch(),
            allocation_set_digest: verified.allocation_set_digest().to_string(),
            total_allocated_invocations: verified.total_allocated_invocations(),
            quota_commitment: pinned.quota_commitment.clone(),
            allocation_set: pinned.allocation_set.clone(),
        };
        Ok(AdmissionCapableEscrowQuota {
            global_quota: source.global_quota().clone(),
            local_quota,
            evidence,
        })
    }

    fn verify_evidence_identity(
        &self,
        evidence: &PartitionEscrowAdmissionEvidence,
    ) -> Result<(), PartitionEscrowRegistryError> {
        if evidence.schema != PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA {
            return Err(PartitionEscrowRegistryError::InvalidEvidenceSchema);
        }
        validate_runtime_evidence(&evidence.resolver)?;
        if evidence.resolver != self.runtime_evidence {
            return Err(PartitionEscrowRegistryError::RuntimeEvidenceMismatch);
        }
        if evidence.durable_store != self.durable_store {
            return Err(PartitionEscrowRegistryError::DurableStoreBindingMismatch);
        }
        if evidence.authority_domain != self.authority_domain
            || evidence.partition_id != self.partition_id
            || evidence.authority_id != self.authority_id
        {
            return Err(PartitionEscrowRegistryError::RegistryIdentityMismatch);
        }
        if evidence.quotas.is_empty() || evidence.quotas.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION
        {
            return Err(PartitionEscrowRegistryError::InvalidAdmissionQuotaCount);
        }
        let mut keys = BTreeSet::new();
        for quota in &evidence.quotas {
            if !keys.insert(quota.quota_key_digest.as_str()) {
                return Err(PartitionEscrowRegistryError::DuplicateAdmissionQuota);
            }
        }
        Ok(())
    }

    fn verify_persisted_quota(
        &self,
        evidence: &PartitionEscrowAdmissionQuotaEvidence,
        verified_at: u64,
    ) -> Result<(), PartitionEscrowRegistryError> {
        evidence.global_quota.validate()?;
        let quota_key_digest = evidence.global_quota.key_digest()?;
        let quota_descriptor_digest = evidence.global_quota.descriptor_digest()?;
        if evidence.quota_key_digest != quota_key_digest
            || evidence.quota_descriptor_digest != quota_descriptor_digest
            || !source_trust_matches_quota(&evidence.global_quota, &evidence.source_trust)
        {
            return Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch);
        }
        let pinned = self
            .allocation_sets
            .get(&quota_key_digest)
            .ok_or(PartitionEscrowRegistryError::MissingAllocationSet)?;
        if pinned.quota_commitment != evidence.quota_commitment
            || pinned.allocation_set != evidence.allocation_set
        {
            return Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch);
        }
        let certificate =
            verify_partition_escrow_quota_commitment(&evidence.quota_commitment, verified_at)?;
        let trust_digest = source_trust_binding_digest(
            &evidence.global_quota,
            &evidence.underlying_source_artifact_digest,
            &evidence.source_signer,
            evidence.source_not_before,
            evidence.source_expires_at,
            &evidence.source_trust,
        )?;
        if certificate.binding_digest()? != evidence.quota_certificate_binding_digest
            || certificate.commitment_digest() != evidence.quota_commitment_digest
            || certificate.underlying_source_artifact_digest()
                != evidence.underlying_source_artifact_digest
            || certificate.source_trust_binding_digest() != trust_digest
            || trust_digest != evidence.source_trust_binding_digest
            || certificate.source_not_before() != evidence.source_not_before
            || certificate.source_expires_at() != evidence.source_expires_at
            || certificate.certificate_signer() != &evidence.source_signer
            || certificate.allocation_plan_digest() != evidence.allocation_plan_digest
            || certificate.allocation_root_id() != evidence.allocation_root_id
            || certificate.allocation_epoch() != evidence.allocation_epoch
        {
            return Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch);
        }
        let context = PartitionEscrowAllocationVerificationContext::new(
            &self.partition_id,
            &self.authority_id,
            &certificate,
        )?;
        let verified = verify_partition_escrow_allocation_set(
            &evidence.allocation_set,
            &context,
            verified_at,
            Some(&evidence.allocation_set_digest),
        )?;
        if verified.local_allocated_invocations() != evidence.local_allocated_invocations
            || verified.total_allocated_invocations() != evidence.total_allocated_invocations
            || evidence.local_allocated_invocations > evidence.global_quota.max_invocations()
        {
            return Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryAllocationPin<'a> {
    quota: &'a PartitionEscrowQuota,
    quota_key_digest: &'a str,
    quota_descriptor_digest: &'a str,
    quota_certificate_binding_digest: &'a str,
    quota_commitment_digest: &'a str,
    underlying_source_artifact_digest: &'a str,
    source_trust_binding_digest: &'a str,
    source_not_before: u64,
    source_expires_at: u64,
    source_signer: &'a PublicKey,
    allocation_plan_digest: &'a str,
    allocation_root_id: &'a str,
    allocation_epoch: u64,
    allocation_set_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryConfigurationBody<'a> {
    schema: &'static str,
    authority_domain: &'a str,
    partition_id: &'a str,
    authority_id: &'a str,
    resolver_id: &'a str,
    resolver_implementation_id: &'a str,
    resolver_implementation_version: u32,
    durable_store: &'a PartitionEscrowDurableStoreEvidence,
    allocation_pins: Vec<RegistryAllocationPin<'a>>,
}

fn registry_configuration_digest(
    input: &PartitionEscrowRegistryInput,
    durable_store: &PartitionEscrowDurableStoreEvidence,
    allocation_sets: &BTreeMap<String, PinnedAllocationSet>,
) -> Result<String, PartitionEscrowRegistryError> {
    let allocation_pins = allocation_sets
        .values()
        .map(|pinned| RegistryAllocationPin {
            quota: pinned.load_certificate.quota(),
            quota_key_digest: &pinned.quota_key_digest,
            quota_descriptor_digest: &pinned.quota_descriptor_digest,
            quota_certificate_binding_digest: &pinned.quota_certificate_binding_digest,
            quota_commitment_digest: &pinned.quota_commitment_digest,
            underlying_source_artifact_digest: pinned
                .load_certificate
                .underlying_source_artifact_digest(),
            source_trust_binding_digest: pinned.load_certificate.source_trust_binding_digest(),
            source_not_before: pinned.load_certificate.source_not_before(),
            source_expires_at: pinned.load_certificate.source_expires_at(),
            source_signer: pinned.load_certificate.certificate_signer(),
            allocation_plan_digest: pinned.load_certificate.allocation_plan_digest(),
            allocation_root_id: pinned.load_certificate.allocation_root_id(),
            allocation_epoch: pinned.load_certificate.allocation_epoch(),
            allocation_set_digest: &pinned.allocation_set_digest,
        })
        .collect();
    let body = RegistryConfigurationBody {
        schema: PARTITION_ESCROW_REGISTRY_SCHEMA,
        authority_domain: &input.authority_domain,
        partition_id: &input.partition_id,
        authority_id: &input.authority_id,
        resolver_id: &input.resolver_id,
        resolver_implementation_id: &input.resolver_implementation_id,
        resolver_implementation_version: input.resolver_implementation_version,
        durable_store,
        allocation_pins,
    };
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| PartitionEscrowRegistryError::Canonicalization(error.to_string()))?;
    let mut digest_input =
        Vec::with_capacity(PARTITION_ESCROW_REGISTRY_DIGEST_DOMAIN.len() + canonical.len());
    digest_input.extend_from_slice(PARTITION_ESCROW_REGISTRY_DIGEST_DOMAIN);
    digest_input.extend_from_slice(&canonical);
    Ok(sha256_hex(&digest_input))
}

fn validate_registry_input(
    input: &PartitionEscrowRegistryInput,
) -> Result<(), PartitionEscrowRegistryError> {
    if input.entries.is_empty() {
        return Err(PartitionEscrowRegistryError::EmptyRegistry);
    }
    if input.entries.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(PartitionEscrowRegistryError::RegistryTooLarge);
    }
    validate_identifier(&input.authority_domain, "authority domain")?;
    validate_identifier(&input.partition_id, "partition id")?;
    validate_identifier(&input.authority_id, "authority id")?;
    validate_identifier(&input.resolver_id, "resolver id")?;
    validate_identifier(
        &input.resolver_implementation_id,
        "resolver implementation id",
    )?;
    if input.resolver_implementation_version == 0 {
        return Err(PartitionEscrowRegistryError::InvalidImplementationVersion);
    }
    validate_digest(&input.store_identity_digest, "store identity digest")?;
    validate_digest(&input.counter_namespace_digest, "counter namespace digest")?;
    if input.fencing_token == 0 {
        return Err(PartitionEscrowRegistryError::DurableStoreBindingMismatch);
    }
    if input.authority_id != input.store_identity_digest
        || input.counter_namespace_digest
            != partition_escrow_counter_namespace_digest(&input.partition_id, &input.authority_id)?
    {
        return Err(PartitionEscrowRegistryError::DurableStoreBindingMismatch);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PartitionEscrowCounterNamespaceBody<'a> {
    partition_id: &'a str,
    authority_id: &'a str,
}

pub fn partition_escrow_counter_namespace_digest(
    partition_id: &str,
    authority_id: &str,
) -> Result<String, PartitionEscrowRegistryError> {
    validate_identifier(partition_id, "partition id")?;
    validate_identifier(authority_id, "authority id")?;
    let canonical = canonical_json_bytes(&PartitionEscrowCounterNamespaceBody {
        partition_id,
        authority_id,
    })
    .map_err(|error| PartitionEscrowRegistryError::Canonicalization(error.to_string()))?;
    let mut input = Vec::with_capacity(
        PARTITION_ESCROW_COUNTER_NAMESPACE_DIGEST_DOMAIN.len() + canonical.len(),
    );
    input.extend_from_slice(PARTITION_ESCROW_COUNTER_NAMESPACE_DIGEST_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

fn validate_ordered_sources(
    sources: &[VerifiedPartitionEscrowQuotaSource],
    now: u64,
) -> Result<(), PartitionEscrowRegistryError> {
    if sources.is_empty() || sources.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(PartitionEscrowRegistryError::InvalidAdmissionQuotaCount);
    }
    let mut keys = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for source in sources {
        source.certificate().validate()?;
        if source.certificate().verified_at() != now {
            return Err(PartitionEscrowRegistryError::SourceNotFresh);
        }
        if !keys.insert(source.quota().key_digest()?)
            || !bindings.insert(source.certificate().binding_digest()?)
        {
            return Err(PartitionEscrowRegistryError::DuplicateAdmissionQuota);
        }
    }
    Ok(())
}

fn validate_runtime_evidence(
    evidence: &PartitionEscrowResolverRuntimeEvidence,
) -> Result<(), PartitionEscrowRegistryError> {
    validate_identifier(&evidence.resolver_id, "resolver id")?;
    validate_identifier(&evidence.implementation_id, "resolver implementation id")?;
    if evidence.implementation_version == 0 {
        return Err(PartitionEscrowRegistryError::InvalidImplementationVersion);
    }
    validate_digest(
        &evidence.configuration_digest,
        "resolver configuration digest",
    )
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PartitionEscrowRegistryError> {
    if value.is_empty()
        || value.len() > MAX_REGISTRY_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(PartitionEscrowRegistryError::InvalidIdentifier(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<(), PartitionEscrowRegistryError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PartitionEscrowRegistryError::InvalidDigest(
            field.to_string(),
        ));
    }
    Ok(())
}
