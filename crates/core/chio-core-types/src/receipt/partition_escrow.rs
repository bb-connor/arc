use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::economics::FinancialPartitionEscrowReceiptMetadata;
use crate::partition_escrow::{
    verify_partition_escrow_allocation_set, verify_partition_escrow_quota_commitment,
    PartitionEscrowAllocationVerificationContext, PartitionEscrowQuota,
    SignedPartitionEscrowAllocationSet, SignedPartitionEscrowQuotaCommitment,
};
use crate::{canonical_json_bytes, sha256_hex, PublicKey};

const PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA: &str =
    "chio.partition-escrow-admission-evidence.v1";
const PARTITION_ESCROW_ADMISSION_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"chio.partition-escrow-admission-evidence.v1\0";
const PARTITION_ESCROW_SOURCE_TRUST_SCHEMA: &str = "chio.partition-escrow-source-trust-binding.v1";
const PARTITION_ESCROW_SOURCE_TRUST_BINDING_DOMAIN: &[u8] =
    b"chio.partition-escrow-source-trust-binding.v1\0";
const PARTITION_ESCROW_COUNTER_NAMESPACE_DOMAIN: &[u8] =
    b"chio.partition-escrow-counter-namespace.v1\0";
const MAX_PARTITION_ESCROW_RECEIPT_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_PARTITION_ESCROW_RECEIPT_QUOTAS: usize = 8;
const MAX_PARTITION_ESCROW_RECEIPT_IDENTIFIER_BYTES: usize = 512;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const GRANT_INVOCATION_PROFILE: &str = "chio.grant-invocation.v1";
const AGGREGATE_CAPABILITY_INVOCATION_PROFILE: &str = "chio.aggregate-capability-invocation.v1";
const AGGREGATE_FAMILY_INVOCATION_PROFILE: &str = "chio.aggregate-family-invocation.v1";
const BROKER_CAPABILITY_EXECUTION_PROFILE: &str = "chio.broker-capability-execution.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowResolverRuntimeEvidence {
    resolver_id: String,
    implementation_id: String,
    implementation_version: u32,
    configuration_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowDurableStoreEvidence {
    store_identity_digest: String,
    counter_namespace_digest: String,
    fencing_token: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum PartitionEscrowSourceTrustEvidence {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowAdmissionQuotaEvidence {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartitionEscrowAdmissionEvidence {
    schema: String,
    verified_at: u64,
    resolver: PartitionEscrowResolverRuntimeEvidence,
    durable_store: PartitionEscrowDurableStoreEvidence,
    authority_domain: String,
    partition_id: String,
    authority_id: String,
    quotas: Vec<PartitionEscrowAdmissionQuotaEvidence>,
}

/// Validate a receipt's complete historical partition-escrow proof without
/// exposing which internal binding failed. This proves canonical and signed
/// structure at the recorded verification time. It does not make the evidence
/// fresh admission authority. Callers deliberately receive one boolean so a
/// denial cannot reveal quota, allocation, signer, or source dimensions.
pub(super) fn is_valid_partition_escrow_receipt_metadata(
    metadata: &FinancialPartitionEscrowReceiptMetadata,
    expected_capability_id: &str,
    expected_grant_index: u32,
) -> bool {
    validate_partition_escrow_receipt_metadata(
        metadata,
        expected_capability_id,
        expected_grant_index,
    )
    .is_ok()
}

fn validate_partition_escrow_receipt_metadata(
    metadata: &FinancialPartitionEscrowReceiptMetadata,
    expected_capability_id: &str,
    expected_grant_index: u32,
) -> Result<(), ()> {
    let canonical = metadata.canonical_json.as_bytes();
    if canonical.is_empty()
        || canonical.len() > MAX_PARTITION_ESCROW_RECEIPT_EVIDENCE_BYTES
        || !is_digest(&metadata.evidence_digest)
    {
        return Err(());
    }
    let evidence: PartitionEscrowAdmissionEvidence =
        serde_json::from_slice(canonical).map_err(|_| ())?;
    let recanonical = canonical_json_bytes(&evidence).map_err(|_| ())?;
    if recanonical.as_slice() != canonical {
        return Err(());
    }
    let mut digest_input = Vec::with_capacity(
        PARTITION_ESCROW_ADMISSION_EVIDENCE_DIGEST_DOMAIN.len() + canonical.len(),
    );
    digest_input.extend_from_slice(PARTITION_ESCROW_ADMISSION_EVIDENCE_DIGEST_DOMAIN);
    digest_input.extend_from_slice(canonical);
    if sha256_hex(&digest_input) != metadata.evidence_digest {
        return Err(());
    }

    validate_evidence_identity(&evidence)?;
    validate_summary(metadata, &evidence)?;
    let mut quota_keys = BTreeSet::new();
    let mut bound_grant_quota_found = false;
    for quota in &evidence.quotas {
        validate_quota_evidence(&evidence, quota)?;
        if !quota_keys.insert(quota.quota_key_digest.as_str()) {
            return Err(());
        }
        if quota.global_quota.profile() == GRANT_INVOCATION_PROFILE {
            let source_matches_receipt = matches!(
                &quota.source_trust,
                PartitionEscrowSourceTrustEvidence::GrantCapability {
                    capability_id,
                    grant_index,
                    ..
                } if capability_id == expected_capability_id
                    && *grant_index == expected_grant_index
            );
            if bound_grant_quota_found
                || quota.global_quota.owner_id() != expected_capability_id
                || quota.global_quota.grant_index() != Some(expected_grant_index)
                || !source_matches_receipt
            {
                return Err(());
            }
            bound_grant_quota_found = true;
        }
    }
    if !bound_grant_quota_found {
        return Err(());
    }
    Ok(())
}

fn validate_evidence_identity(evidence: &PartitionEscrowAdmissionEvidence) -> Result<(), ()> {
    if evidence.schema != PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA
        || evidence.verified_at > MAX_SAFE_JSON_INTEGER
        || evidence.quotas.is_empty()
        || evidence.quotas.len() > MAX_PARTITION_ESCROW_RECEIPT_QUOTAS
        || !is_identifier(&evidence.resolver.resolver_id)
        || !is_identifier(&evidence.resolver.implementation_id)
        || evidence.resolver.implementation_version == 0
        || !is_digest(&evidence.resolver.configuration_digest)
        || !is_digest(&evidence.durable_store.store_identity_digest)
        || !is_digest(&evidence.durable_store.counter_namespace_digest)
        || evidence.durable_store.fencing_token == 0
        || evidence.durable_store.fencing_token > MAX_SAFE_JSON_INTEGER
        || !is_identifier(&evidence.authority_domain)
        || !is_identifier(&evidence.partition_id)
        || !is_identifier(&evidence.authority_id)
        || evidence.authority_id != evidence.durable_store.store_identity_digest
    {
        return Err(());
    }
    if partition_escrow_counter_namespace_digest(&evidence.partition_id, &evidence.authority_id)?
        != evidence.durable_store.counter_namespace_digest
    {
        return Err(());
    }
    Ok(())
}

fn validate_summary(
    metadata: &FinancialPartitionEscrowReceiptMetadata,
    evidence: &PartitionEscrowAdmissionEvidence,
) -> Result<(), ()> {
    let summary = &metadata.summary;
    if summary.resolver_id != evidence.resolver.resolver_id
        || summary.resolver_implementation_id != evidence.resolver.implementation_id
        || summary.resolver_implementation_version != evidence.resolver.implementation_version
        || summary.resolver_configuration_digest != evidence.resolver.configuration_digest
        || summary.store_identity_digest != evidence.durable_store.store_identity_digest
        || summary.counter_namespace_digest != evidence.durable_store.counter_namespace_digest
        || summary.fencing_token != evidence.durable_store.fencing_token
        || summary.partition_id != evidence.partition_id
        || summary.authority_id != evidence.authority_id
    {
        return Err(());
    }
    Ok(())
}

fn validate_quota_evidence(
    admission: &PartitionEscrowAdmissionEvidence,
    evidence: &PartitionEscrowAdmissionQuotaEvidence,
) -> Result<(), ()> {
    evidence.global_quota.validate().map_err(|_| ())?;
    if !is_digest(&evidence.quota_key_digest)
        || !is_digest(&evidence.quota_descriptor_digest)
        || !is_digest(&evidence.quota_certificate_binding_digest)
        || !is_digest(&evidence.quota_commitment_digest)
        || !is_digest(&evidence.underlying_source_artifact_digest)
        || !is_digest(&evidence.source_trust_binding_digest)
        || !is_digest(&evidence.allocation_plan_digest)
        || !is_identifier(&evidence.allocation_root_id)
        || !is_digest(&evidence.allocation_set_digest)
        || evidence.source_not_before > MAX_SAFE_JSON_INTEGER
        || evidence.source_expires_at > MAX_SAFE_JSON_INTEGER
        || evidence.source_expires_at <= evidence.source_not_before
        || evidence.allocation_epoch != admission.durable_store.fencing_token
    {
        return Err(());
    }
    validate_source_trust(&evidence.global_quota, &evidence.source_trust)?;
    if evidence.global_quota.key_digest().map_err(|_| ())? != evidence.quota_key_digest
        || evidence.global_quota.descriptor_digest().map_err(|_| ())?
            != evidence.quota_descriptor_digest
    {
        return Err(());
    }

    let commitment_bytes = canonical_json_bytes(&evidence.quota_commitment).map_err(|_| ())?;
    let commitment =
        SignedPartitionEscrowQuotaCommitment::from_canonical_json_bytes(&commitment_bytes)
            .map_err(|_| ())?;
    let certificate = verify_partition_escrow_quota_commitment(&commitment, admission.verified_at)
        .map_err(|_| ())?;
    let source_trust_digest = source_trust_binding_digest(evidence)?;
    if certificate.authority_domain() != admission.authority_domain
        || certificate.quota() != &evidence.global_quota
        || certificate.binding_digest().map_err(|_| ())?
            != evidence.quota_certificate_binding_digest
        || certificate.commitment_digest() != evidence.quota_commitment_digest
        || certificate.underlying_source_artifact_digest()
            != evidence.underlying_source_artifact_digest
        || certificate.source_trust_binding_digest() != source_trust_digest
        || source_trust_digest != evidence.source_trust_binding_digest
        || certificate.source_not_before() != evidence.source_not_before
        || certificate.source_expires_at() != evidence.source_expires_at
        || certificate.certificate_signer() != &evidence.source_signer
        || certificate.allocation_plan_digest() != evidence.allocation_plan_digest
        || certificate.allocation_root_id() != evidence.allocation_root_id
        || certificate.allocation_epoch() != evidence.allocation_epoch
    {
        return Err(());
    }

    let allocation_bytes = canonical_json_bytes(&evidence.allocation_set).map_err(|_| ())?;
    let allocation_set =
        SignedPartitionEscrowAllocationSet::from_canonical_json_bytes(&allocation_bytes)
            .map_err(|_| ())?;
    let context = PartitionEscrowAllocationVerificationContext::new(
        admission.partition_id.as_str(),
        admission.authority_id.as_str(),
        &certificate,
    )
    .map_err(|_| ())?;
    let allocation = verify_partition_escrow_allocation_set(
        &allocation_set,
        &context,
        admission.verified_at,
        Some(&evidence.allocation_set_digest),
    )
    .map_err(|_| ())?;
    if allocation.local_allocated_invocations() != evidence.local_allocated_invocations
        || allocation.total_allocated_invocations() != evidence.total_allocated_invocations
        || evidence.local_allocated_invocations > evidence.global_quota.max_invocations()
    {
        return Err(());
    }
    Ok(())
}

fn source_trust_binding_digest(
    evidence: &PartitionEscrowAdmissionQuotaEvidence,
) -> Result<String, ()> {
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

    let binding = SourceTrustBinding {
        schema: PARTITION_ESCROW_SOURCE_TRUST_SCHEMA,
        profile: evidence.global_quota.profile(),
        quota_key_digest: evidence.global_quota.key_digest().map_err(|_| ())?,
        quota_descriptor_digest: evidence.global_quota.descriptor_digest().map_err(|_| ())?,
        underlying_source_artifact_digest: &evidence.underlying_source_artifact_digest,
        source_signer: &evidence.source_signer,
        source_not_before: evidence.source_not_before,
        source_expires_at: evidence.source_expires_at,
        profile_trust: &evidence.source_trust,
    };
    let canonical = canonical_json_bytes(&binding).map_err(|_| ())?;
    let mut digest_input =
        Vec::with_capacity(PARTITION_ESCROW_SOURCE_TRUST_BINDING_DOMAIN.len() + canonical.len());
    digest_input.extend_from_slice(PARTITION_ESCROW_SOURCE_TRUST_BINDING_DOMAIN);
    digest_input.extend_from_slice(&canonical);
    Ok(sha256_hex(&digest_input))
}

fn partition_escrow_counter_namespace_digest(
    partition_id: &str,
    authority_id: &str,
) -> Result<String, ()> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CounterNamespace<'a> {
        partition_id: &'a str,
        authority_id: &'a str,
    }

    let canonical = canonical_json_bytes(&CounterNamespace {
        partition_id,
        authority_id,
    })
    .map_err(|_| ())?;
    let mut digest_input =
        Vec::with_capacity(PARTITION_ESCROW_COUNTER_NAMESPACE_DOMAIN.len() + canonical.len());
    digest_input.extend_from_slice(PARTITION_ESCROW_COUNTER_NAMESPACE_DOMAIN);
    digest_input.extend_from_slice(&canonical);
    Ok(sha256_hex(&digest_input))
}

fn validate_source_trust(
    quota: &PartitionEscrowQuota,
    evidence: &PartitionEscrowSourceTrustEvidence,
) -> Result<(), ()> {
    match evidence {
        PartitionEscrowSourceTrustEvidence::GrantCapability {
            capability_id,
            grant_index,
            revocation_set_digest,
        } => {
            if quota.profile() != GRANT_INVOCATION_PROFILE
                || quota.owner_id() != capability_id
                || quota.grant_index() != Some(*grant_index)
                || !is_identifier(capability_id)
                || !is_digest(revocation_set_digest)
            {
                return Err(());
            }
        }
        PartitionEscrowSourceTrustEvidence::AggregateCapability {
            capability_id,
            revocation_set_digest,
        } => {
            if quota.profile() != AGGREGATE_CAPABILITY_INVOCATION_PROFILE
                || quota.owner_id() != capability_id
                || !is_identifier(capability_id)
                || !is_digest(revocation_set_digest)
            {
                return Err(());
            }
        }
        PartitionEscrowSourceTrustEvidence::AggregateFamily {
            root_capability_id,
            root_binding_digest,
            family_owner,
            revocation_set_digest,
        } => {
            if quota.profile() != AGGREGATE_FAMILY_INVOCATION_PROFILE
                || quota.owner_id() != family_owner
                || !is_identifier(root_capability_id)
                || !is_digest(root_binding_digest)
                || !is_digest(family_owner)
                || !is_digest(revocation_set_digest)
            {
                return Err(());
            }
        }
        PartitionEscrowSourceTrustEvidence::BrokerCapability {
            verifier_id,
            broker_capability_id,
            quota_owner_id,
            request_constraint_digest,
            request_binding_hash,
            negotiated_features_digest,
            claim_binding_digest,
            revocation_set_digest,
        } => {
            if quota.profile() != BROKER_CAPABILITY_EXECUTION_PROFILE
                || quota.owner_id() != quota_owner_id
                || !is_identifier(verifier_id)
                || !is_identifier(broker_capability_id)
                || !is_digest(quota_owner_id)
                || !is_digest(request_constraint_digest)
                || !is_digest(request_binding_hash)
                || !is_digest(negotiated_features_digest)
                || !is_digest(claim_binding_digest)
                || !is_digest(revocation_set_digest)
            {
                return Err(());
            }
        }
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PARTITION_ESCROW_RECEIPT_IDENTIFIER_BYTES
        && !value.bytes().any(|byte| byte == 0)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
