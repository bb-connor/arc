use chio_core::capability::aggregate_budget::{
    AggregateInvocationScope, VerifiedAggregateInvocationAuthority,
};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::PublicKey;
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_core_types::partition_escrow::{
    verify_partition_escrow_quota_commitment, PartitionEscrowQuota,
    SignedPartitionEscrowQuotaCommitment, VerifiedPartitionEscrowQuotaCertificate,
};
use serde::{Deserialize, Serialize};

use super::error::PartitionEscrowRegistryError;
use crate::budget_store::{BudgetInvocationQuota, BudgetQuotaProfile, VerifiedInvocationAdmission};
use crate::supplemental_quota::VerifiedSupplementalQuota;
use crate::threshold_approval::authorization_capability_hash;

const PARTITION_ESCROW_SOURCE_TRUST_SCHEMA: &str = "chio.partition-escrow-source-trust-binding.v1";
const PARTITION_ESCROW_SOURCE_TRUST_BINDING_DOMAIN: &[u8] =
    b"chio.partition-escrow-source-trust-binding.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum PartitionEscrowSourceTrustEvidence {
    GrantCapability {
        capability_id: String,
        grant_index: u32,
        revocation_set_digest: String,
    },
    AggregateCapability {
        capability_id: String,
        revocation_set_digest: String,
    },
    AggregateFamily {
        root_capability_id: String,
        root_binding_digest: String,
        family_owner: String,
        revocation_set_digest: String,
    },
    BrokerCapability {
        verifier_id: String,
        broker_capability_id: String,
        quota_owner_id: String,
        request_constraint_digest: String,
        request_binding_hash: String,
        negotiated_features_digest: String,
        claim_binding_digest: String,
        revocation_set_digest: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedPartitionEscrowQuotaSource {
    global_quota: BudgetInvocationQuota,
    quota: PartitionEscrowQuota,
    quota_commitment: SignedPartitionEscrowQuotaCommitment,
    certificate: VerifiedPartitionEscrowQuotaCertificate,
    trust_evidence: PartitionEscrowSourceTrustEvidence,
}

struct VerifiedSourceBinding {
    quota: PartitionEscrowQuota,
    underlying_source_artifact_digest: String,
    source_signer: PublicKey,
    source_not_before: u64,
    source_expires_at: u64,
    trust_evidence: PartitionEscrowSourceTrustEvidence,
}

impl VerifiedPartitionEscrowQuotaSource {
    pub(super) fn global_quota(&self) -> &BudgetInvocationQuota {
        &self.global_quota
    }

    pub(super) fn quota(&self) -> &PartitionEscrowQuota {
        &self.quota
    }

    pub(super) fn quota_commitment(&self) -> &SignedPartitionEscrowQuotaCommitment {
        &self.quota_commitment
    }

    pub(super) fn certificate(&self) -> &VerifiedPartitionEscrowQuotaCertificate {
        &self.certificate
    }

    pub(super) fn trust_evidence(&self) -> &PartitionEscrowSourceTrustEvidence {
        &self.trust_evidence
    }
}

pub(crate) fn verify_grant_partition_escrow_source(
    commitment: &SignedPartitionEscrowQuotaCommitment,
    capability: &CapabilityToken,
    admission: &VerifiedInvocationAdmission,
    grant_index: usize,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaSource, PartitionEscrowRegistryError> {
    verify_capability_fresh(capability, now)?;
    let grant_index = u32::try_from(grant_index).map_err(|_| {
        PartitionEscrowRegistryError::SourceVerification(
            "grant index exceeds the partition escrow wire range".to_string(),
        )
    })?;
    let global_quota = exact_admission_quota(
        admission,
        BudgetQuotaProfile::GrantInvocation,
        &capability.id,
        Some(grant_index),
    )?;
    let quota = partition_quota(global_quota)?;
    let artifact_digest = capability_artifact_digest(capability)?;
    let trust_evidence = PartitionEscrowSourceTrustEvidence::GrantCapability {
        capability_id: capability.id.clone(),
        grant_index,
        revocation_set_digest: admission.revocation_set().digest().to_string(),
    };
    bind_verified_source(
        commitment,
        global_quota,
        VerifiedSourceBinding {
            quota,
            underlying_source_artifact_digest: artifact_digest,
            source_signer: capability.issuer.clone(),
            source_not_before: capability.issued_at,
            source_expires_at: capability.expires_at,
            trust_evidence,
        },
        now,
    )
}

pub(crate) fn verify_aggregate_capability_partition_escrow_source(
    commitment: &SignedPartitionEscrowQuotaCommitment,
    capability: &CapabilityToken,
    aggregate: &VerifiedAggregateInvocationAuthority,
    admission: &VerifiedInvocationAdmission,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaSource, PartitionEscrowRegistryError> {
    verify_capability_fresh(capability, now)?;
    if aggregate.scope() != AggregateInvocationScope::Capability
        || aggregate.owner() != capability.id
    {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "aggregate capability owner",
        ));
    }
    let global_quota = exact_admission_quota(
        admission,
        BudgetQuotaProfile::AggregateCapabilityInvocation,
        aggregate.owner(),
        None,
    )?;
    if global_quota.max_invocations() != aggregate.max_invocations() {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "aggregate capability maximum",
        ));
    }
    let quota = partition_quota(global_quota)?;
    let artifact_digest = capability_artifact_digest(capability)?;
    let trust_evidence = PartitionEscrowSourceTrustEvidence::AggregateCapability {
        capability_id: capability.id.clone(),
        revocation_set_digest: admission.revocation_set().digest().to_string(),
    };
    bind_verified_source(
        commitment,
        global_quota,
        VerifiedSourceBinding {
            quota,
            underlying_source_artifact_digest: artifact_digest,
            source_signer: capability.issuer.clone(),
            source_not_before: capability.issued_at,
            source_expires_at: capability.expires_at,
            trust_evidence,
        },
        now,
    )
}

pub(crate) fn verify_aggregate_family_partition_escrow_source(
    commitment: &SignedPartitionEscrowQuotaCommitment,
    aggregate: &VerifiedAggregateInvocationAuthority,
    admission: &VerifiedInvocationAdmission,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaSource, PartitionEscrowRegistryError> {
    let root =
        aggregate
            .family_root()
            .ok_or(PartitionEscrowRegistryError::SourceBindingMismatch(
                "aggregate family root",
            ))?;
    if now < root.root_issued_at() || now >= root.root_expires_at() {
        return Err(PartitionEscrowRegistryError::SourceNotFresh);
    }
    let global_quota = exact_admission_quota(
        admission,
        BudgetQuotaProfile::AggregateFamilyInvocation,
        root.family_owner(),
        None,
    )?;
    if global_quota.max_invocations() != root.max_invocations() {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "aggregate family maximum",
        ));
    }
    let quota = partition_quota(global_quota)?;
    let trust_evidence = PartitionEscrowSourceTrustEvidence::AggregateFamily {
        root_capability_id: root.root_capability_id().to_string(),
        root_binding_digest: root.root_binding_digest().to_string(),
        family_owner: root.family_owner().to_string(),
        revocation_set_digest: admission.revocation_set().digest().to_string(),
    };
    bind_verified_source(
        commitment,
        global_quota,
        VerifiedSourceBinding {
            quota,
            underlying_source_artifact_digest: root.root_binding_digest().to_string(),
            source_signer: root.root_issuer().clone(),
            source_not_before: root.root_issued_at(),
            source_expires_at: root.root_expires_at(),
            trust_evidence,
        },
        now,
    )
}

pub(crate) fn verify_broker_partition_escrow_source(
    commitment: &SignedPartitionEscrowQuotaCommitment,
    supplemental: &VerifiedSupplementalQuota,
    admission: &VerifiedInvocationAdmission,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaSource, PartitionEscrowRegistryError> {
    if supplemental.verified_at() != now
        || now < supplemental.not_before()
        || now >= supplemental.expires_at()
    {
        return Err(PartitionEscrowRegistryError::SourceNotFresh);
    }
    let global_quota = exact_admission_quota(
        admission,
        BudgetQuotaProfile::SupplementalBrokerExecution,
        supplemental.quota().key().owner_id(),
        None,
    )?;
    if global_quota != supplemental.quota() {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "broker quota projection",
        ));
    }
    let evidence = admission.evidence();
    if evidence.supplemental_artifact_digest() != Some(supplemental.artifact_digest())
        || evidence.supplemental_verifier_id() != Some(supplemental.verifier_id())
        || evidence.supplemental_claim_binding_digest() != Some(supplemental.claim_binding_digest())
        || evidence.supplemental_issuer() != Some(supplemental.issuer())
        || evidence.supplemental_not_before() != Some(supplemental.not_before())
        || evidence.supplemental_expires_at() != Some(supplemental.expires_at())
        || evidence.supplemental_verified_at() != Some(now)
    {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "broker verified admission provenance",
        ));
    }
    let quota = partition_quota(global_quota)?;
    let trust_evidence = PartitionEscrowSourceTrustEvidence::BrokerCapability {
        verifier_id: supplemental.verifier_id().to_string(),
        broker_capability_id: supplemental.broker_capability_id().to_string(),
        quota_owner_id: supplemental.quota().key().owner_id().to_string(),
        request_constraint_digest: supplemental.request_constraint_digest().to_string(),
        request_binding_hash: supplemental.request_binding_hash().to_string(),
        negotiated_features_digest: supplemental.negotiated_features_digest().to_string(),
        claim_binding_digest: supplemental.claim_binding_digest().to_string(),
        revocation_set_digest: admission.revocation_set().digest().to_string(),
    };
    bind_verified_source(
        commitment,
        global_quota,
        VerifiedSourceBinding {
            quota,
            underlying_source_artifact_digest: supplemental.artifact_digest().to_string(),
            source_signer: supplemental.issuer().clone(),
            source_not_before: supplemental.not_before(),
            source_expires_at: supplemental.expires_at(),
            trust_evidence,
        },
        now,
    )
}

fn bind_verified_source(
    commitment: &SignedPartitionEscrowQuotaCommitment,
    global_quota: &BudgetInvocationQuota,
    binding: VerifiedSourceBinding,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaSource, PartitionEscrowRegistryError> {
    let VerifiedSourceBinding {
        quota,
        underlying_source_artifact_digest,
        source_signer,
        source_not_before,
        source_expires_at,
        trust_evidence,
    } = binding;
    if !source_trust_matches_quota(&quota, &trust_evidence) {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "source trust quota owner and profile",
        ));
    }
    let certificate = verify_partition_escrow_quota_commitment(commitment, now)?;
    if certificate.quota() != &quota {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "derived quota projection",
        ));
    }
    if certificate.underlying_source_artifact_digest() != underlying_source_artifact_digest {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "underlying source artifact digest",
        ));
    }
    if certificate.certificate_signer() != &source_signer {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "source signer",
        ));
    }
    if certificate.source_not_before() != source_not_before
        || certificate.source_expires_at() != source_expires_at
        || certificate.verified_at() != now
    {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "source activation or expiry",
        ));
    }
    let source_trust_binding_digest = source_trust_binding_digest(
        &quota,
        &underlying_source_artifact_digest,
        &source_signer,
        source_not_before,
        source_expires_at,
        &trust_evidence,
    )?;
    if certificate.source_trust_binding_digest() != source_trust_binding_digest {
        return Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "kernel-derived source trust binding",
        ));
    }
    Ok(VerifiedPartitionEscrowQuotaSource {
        global_quota: global_quota.clone(),
        quota,
        quota_commitment: commitment.clone(),
        certificate,
        trust_evidence,
    })
}

pub(super) fn source_trust_matches_quota(
    quota: &PartitionEscrowQuota,
    trust_evidence: &PartitionEscrowSourceTrustEvidence,
) -> bool {
    match trust_evidence {
        PartitionEscrowSourceTrustEvidence::GrantCapability {
            capability_id,
            grant_index,
            ..
        } => {
            quota.profile() == BudgetQuotaProfile::GrantInvocation.as_str()
                && quota.owner_id() == capability_id
                && quota.grant_index() == Some(*grant_index)
        }
        PartitionEscrowSourceTrustEvidence::AggregateCapability { capability_id, .. } => {
            quota.profile() == BudgetQuotaProfile::AggregateCapabilityInvocation.as_str()
                && quota.owner_id() == capability_id
                && quota.grant_index().is_none()
        }
        PartitionEscrowSourceTrustEvidence::AggregateFamily { family_owner, .. } => {
            quota.profile() == BudgetQuotaProfile::AggregateFamilyInvocation.as_str()
                && quota.owner_id() == family_owner
                && quota.grant_index().is_none()
        }
        PartitionEscrowSourceTrustEvidence::BrokerCapability { quota_owner_id, .. } => {
            quota.profile() == BudgetQuotaProfile::SupplementalBrokerExecution.as_str()
                && quota.owner_id() == quota_owner_id
                && quota.grant_index().is_none()
        }
    }
}

pub(super) fn source_trust_binding_digest(
    quota: &PartitionEscrowQuota,
    underlying_source_artifact_digest: &str,
    source_signer: &PublicKey,
    source_not_before: u64,
    source_expires_at: u64,
    trust_evidence: &PartitionEscrowSourceTrustEvidence,
) -> Result<String, PartitionEscrowRegistryError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceTrustBinding<'a> {
        schema: &'static str,
        profile: &'a str,
        quota_key_digest: String,
        quota_descriptor_digest: String,
        underlying_source_artifact_digest: &'a str,
        source_signer: &'a PublicKey,
        source_not_before: u64,
        source_expires_at: u64,
        profile_trust: &'a PartitionEscrowSourceTrustEvidence,
    }

    let body = SourceTrustBinding {
        schema: PARTITION_ESCROW_SOURCE_TRUST_SCHEMA,
        profile: quota.profile(),
        quota_key_digest: quota.key_digest()?,
        quota_descriptor_digest: quota.descriptor_digest()?,
        underlying_source_artifact_digest,
        source_signer,
        source_not_before,
        source_expires_at,
        profile_trust: trust_evidence,
    };
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| PartitionEscrowRegistryError::Canonicalization(error.to_string()))?;
    let mut input =
        Vec::with_capacity(PARTITION_ESCROW_SOURCE_TRUST_BINDING_DOMAIN.len() + canonical.len());
    input.extend_from_slice(PARTITION_ESCROW_SOURCE_TRUST_BINDING_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

fn exact_admission_quota<'a>(
    admission: &'a VerifiedInvocationAdmission,
    profile: BudgetQuotaProfile,
    owner_id: &str,
    grant_index: Option<u32>,
) -> Result<&'a BudgetInvocationQuota, PartitionEscrowRegistryError> {
    admission
        .quotas()
        .iter()
        .find(|quota| {
            quota.key().profile() == profile
                && quota.key().owner_id() == owner_id
                && quota.key().grant_index() == grant_index
        })
        .ok_or(PartitionEscrowRegistryError::SourceBindingMismatch(
            "verified admission quota",
        ))
}

fn partition_quota(
    quota: &BudgetInvocationQuota,
) -> Result<PartitionEscrowQuota, PartitionEscrowRegistryError> {
    PartitionEscrowQuota::new(
        quota.key().profile().as_str(),
        quota.key().owner_id(),
        quota.key().grant_index(),
        quota.max_invocations(),
    )
    .map_err(PartitionEscrowRegistryError::from)
}

fn capability_artifact_digest(
    capability: &CapabilityToken,
) -> Result<String, PartitionEscrowRegistryError> {
    authorization_capability_hash(capability)
        .map_err(|error| PartitionEscrowRegistryError::SourceVerification(error.to_string()))
}

fn verify_capability_fresh(
    capability: &CapabilityToken,
    now: u64,
) -> Result<(), PartitionEscrowRegistryError> {
    match capability.verify_signature_at(now) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PartitionEscrowRegistryError::SourceVerification(
            "capability source signature is invalid".to_string(),
        )),
        Err(error) => Err(PartitionEscrowRegistryError::SourceVerification(
            error.to_string(),
        )),
    }
}

#[cfg(test)]
pub(super) fn test_source_trust_binding_digest(
    quota: &PartitionEscrowQuota,
    underlying_source_artifact_digest: &str,
    source_signer: &PublicKey,
    source_not_before: u64,
    source_expires_at: u64,
    trust_evidence: &PartitionEscrowSourceTrustEvidence,
) -> Result<String, PartitionEscrowRegistryError> {
    source_trust_binding_digest(
        quota,
        underlying_source_artifact_digest,
        source_signer,
        source_not_before,
        source_expires_at,
        trust_evidence,
    )
}
