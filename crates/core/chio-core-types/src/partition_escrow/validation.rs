use alloc::string::String;
use core::cmp::Ordering;

use super::artifact::{
    PartitionEscrowAllocation, SignedPartitionEscrowAllocationSet,
    MAX_PARTITION_ESCROW_ALLOCATIONS, MAX_PARTITION_ESCROW_IDENTIFIER_BYTES,
};
use super::commitment::VerifiedPartitionEscrowQuotaCertificate;
use super::error::PartitionEscrowValidationError;

pub(super) const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionEscrowAllocationVerificationContext {
    authority_domain: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    partition_id: String,
    authority_id: String,
    quota_certificate: VerifiedPartitionEscrowQuotaCertificate,
}

impl PartitionEscrowAllocationVerificationContext {
    pub fn new(
        partition_id: impl Into<String>,
        authority_id: impl Into<String>,
        quota_certificate: &VerifiedPartitionEscrowQuotaCertificate,
    ) -> Result<Self, PartitionEscrowValidationError> {
        let context = Self {
            authority_domain: quota_certificate.authority_domain().into(),
            allocation_root_id: quota_certificate.allocation_root_id().into(),
            allocation_epoch: quota_certificate.allocation_epoch(),
            partition_id: partition_id.into(),
            authority_id: authority_id.into(),
            quota_certificate: quota_certificate.clone(),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_identifier(&self.authority_domain, "authority domain")?;
        validate_identifier(&self.allocation_root_id, "allocation root id")?;
        validate_identifier(&self.partition_id, "partition id")?;
        validate_identifier(&self.authority_id, "authority id")?;
        if self.allocation_epoch == 0 || self.allocation_epoch > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
        }
        self.quota_certificate.validate()
    }

    pub fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub fn allocation_root_id(&self) -> &str {
        &self.allocation_root_id
    }

    pub const fn allocation_epoch(&self) -> u64 {
        self.allocation_epoch
    }

    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub const fn quota_certificate(&self) -> &VerifiedPartitionEscrowQuotaCertificate {
        &self.quota_certificate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructurallyVerifiedPartitionEscrowAllocation {
    allocation_set_digest: String,
    quota_certificate_binding_digest: String,
    quota_commitment_digest: String,
    underlying_source_artifact_digest: String,
    source_trust_binding_digest: String,
    allocation_plan_digest: String,
    local_allocated_invocations: u32,
    total_allocated_invocations: u64,
}

impl StructurallyVerifiedPartitionEscrowAllocation {
    pub fn allocation_set_digest(&self) -> &str {
        &self.allocation_set_digest
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

    pub fn allocation_plan_digest(&self) -> &str {
        &self.allocation_plan_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPartitionEscrowAllocation {
    allocation_set_digest: String,
    quota_certificate_binding_digest: String,
    quota_commitment_digest: String,
    underlying_source_artifact_digest: String,
    source_trust_binding_digest: String,
    allocation_plan_digest: String,
    local_allocated_invocations: u32,
    total_allocated_invocations: u64,
}

impl VerifiedPartitionEscrowAllocation {
    pub fn allocation_set_digest(&self) -> &str {
        &self.allocation_set_digest
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

    pub fn allocation_plan_digest(&self) -> &str {
        &self.allocation_plan_digest
    }

    pub const fn local_allocated_invocations(&self) -> u32 {
        self.local_allocated_invocations
    }

    pub const fn total_allocated_invocations(&self) -> u64 {
        self.total_allocated_invocations
    }
}

/// Verifies immutable certificate binding, signature, and digest pin.
///
/// This is appropriate for structural registry loading. It deliberately does
/// not authenticate the certificate's referenced source and does not claim
/// that the allocation is currently within its validity window.
pub fn verify_partition_escrow_allocation_set_structure(
    allocation_set: &SignedPartitionEscrowAllocationSet,
    context: &PartitionEscrowAllocationVerificationContext,
    expected_allocation_set_digest: Option<&str>,
) -> Result<StructurallyVerifiedPartitionEscrowAllocation, PartitionEscrowValidationError> {
    context.validate()?;
    let body = allocation_set.body();
    body.validate_structure()?;
    if body.authority_domain() != context.authority_domain() {
        return Err(PartitionEscrowValidationError::AuthorityDomainMismatch);
    }
    if body.allocation_root_id() != context.allocation_root_id() {
        return Err(PartitionEscrowValidationError::AllocationRootMismatch);
    }
    if body.allocation_epoch() != context.allocation_epoch() {
        return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
    }

    let quota_certificate = context.quota_certificate();
    if body.quota() != quota_certificate.quota() {
        return Err(PartitionEscrowValidationError::QuotaMismatch);
    }
    if body.quota_commitment_digest() != quota_certificate.commitment_digest() {
        return Err(PartitionEscrowValidationError::QuotaAuthorityDigestMismatch);
    }
    if body.quota_commitment_expires_at() != quota_certificate.source_expires_at() {
        return Err(PartitionEscrowValidationError::QuotaAuthorityExpiryMismatch);
    }
    if body.not_before() < quota_certificate.source_not_before() {
        return Err(PartitionEscrowValidationError::AllocationPredatesQuotaAuthority);
    }
    if body.allocation_plan_digest() != quota_certificate.allocation_plan_digest() {
        return Err(PartitionEscrowValidationError::AllocationPlanDigestMismatch);
    }
    if body.expires_at() > quota_certificate.source_expires_at() {
        return Err(PartitionEscrowValidationError::AllocationOutlivesQuotaAuthority);
    }
    if allocation_set.allocator_key() != quota_certificate.certificate_signer() {
        return Err(PartitionEscrowValidationError::SignerMismatch);
    }
    if allocation_set.allocator_key().algorithm() != allocation_set.algorithm()
        || allocation_set.signature().algorithm() != allocation_set.algorithm()
    {
        return Err(PartitionEscrowValidationError::SignatureAlgorithmMismatch);
    }
    if !allocation_set.verify_signature()? {
        return Err(PartitionEscrowValidationError::SignatureInvalid);
    }

    if let Some(expected_digest) = expected_allocation_set_digest {
        validate_digest(expected_digest, "expected allocation set digest")?;
    }
    let allocation_set_digest = allocation_set.digest()?;
    if expected_allocation_set_digest.is_some_and(|expected| expected != allocation_set_digest) {
        return Err(PartitionEscrowValidationError::AllocationSetDigestMismatch);
    }

    let mut local_allocated_invocations = None;
    let mut total_allocated_invocations = 0_u64;
    for allocation in body.allocations() {
        total_allocated_invocations = total_allocated_invocations
            .checked_add(u64::from(allocation.allocated_invocations()))
            .ok_or(PartitionEscrowValidationError::AllocationSumOverflow)?;
        if allocation.partition_id() == context.partition_id()
            && allocation.authority_id() == context.authority_id()
            && local_allocated_invocations
                .replace(allocation.allocated_invocations())
                .is_some()
        {
            return Err(PartitionEscrowValidationError::MultipleLocalAllocations);
        }
    }
    if total_allocated_invocations > u64::from(quota_certificate.quota().max_invocations()) {
        return Err(PartitionEscrowValidationError::AllocationSumExceeded {
            allocated: total_allocated_invocations,
            maximum: quota_certificate.quota().max_invocations(),
        });
    }
    let local_allocated_invocations = local_allocated_invocations
        .ok_or(PartitionEscrowValidationError::MissingLocalAllocation)?;
    Ok(StructurallyVerifiedPartitionEscrowAllocation {
        allocation_set_digest,
        quota_certificate_binding_digest: quota_certificate.binding_digest()?,
        quota_commitment_digest: body.quota_commitment_digest().into(),
        underlying_source_artifact_digest: quota_certificate
            .underlying_source_artifact_digest()
            .into(),
        source_trust_binding_digest: quota_certificate.source_trust_binding_digest().into(),
        allocation_plan_digest: body.allocation_plan_digest().into(),
        local_allocated_invocations,
        total_allocated_invocations,
    })
}

/// Verifies the immutable contract and requires it to be fresh at `now`.
pub fn verify_partition_escrow_allocation_set(
    allocation_set: &SignedPartitionEscrowAllocationSet,
    context: &PartitionEscrowAllocationVerificationContext,
    now: u64,
    expected_allocation_set_digest: Option<&str>,
) -> Result<VerifiedPartitionEscrowAllocation, PartitionEscrowValidationError> {
    allocation_set.body().validate_at(now)?;
    let structural = verify_partition_escrow_allocation_set_structure(
        allocation_set,
        context,
        expected_allocation_set_digest,
    )?;
    Ok(VerifiedPartitionEscrowAllocation {
        allocation_set_digest: structural.allocation_set_digest,
        quota_certificate_binding_digest: structural.quota_certificate_binding_digest,
        quota_commitment_digest: structural.quota_commitment_digest,
        underlying_source_artifact_digest: structural.underlying_source_artifact_digest,
        source_trust_binding_digest: structural.source_trust_binding_digest,
        allocation_plan_digest: structural.allocation_plan_digest,
        local_allocated_invocations: structural.local_allocated_invocations,
        total_allocated_invocations: structural.total_allocated_invocations,
    })
}

pub(super) fn validate_allocations(
    allocations: &[PartitionEscrowAllocation],
    maximum: u32,
) -> Result<(), PartitionEscrowValidationError> {
    if allocations.is_empty() || allocations.len() > MAX_PARTITION_ESCROW_ALLOCATIONS {
        return Err(PartitionEscrowValidationError::InvalidAllocationCount);
    }
    for allocation in allocations {
        allocation.validate()?;
    }
    for (index, allocation) in allocations.iter().enumerate() {
        for candidate in &allocations[index + 1..] {
            if allocation.partition_id().as_bytes() == candidate.partition_id().as_bytes() {
                return Err(PartitionEscrowValidationError::DuplicatePartitionId);
            }
            if allocation.authority_id().as_bytes() == candidate.authority_id().as_bytes() {
                return Err(PartitionEscrowValidationError::DuplicateAuthorityId);
            }
        }
    }
    for pair in allocations.windows(2) {
        if compare_allocations(&pair[0], &pair[1]) != Ordering::Less {
            return Err(PartitionEscrowValidationError::AllocationOrder);
        }
    }
    let allocated = allocations.iter().try_fold(0_u64, |sum, allocation| {
        sum.checked_add(u64::from(allocation.allocated_invocations()))
            .ok_or(PartitionEscrowValidationError::AllocationSumOverflow)
    })?;
    if allocated > u64::from(maximum) {
        return Err(PartitionEscrowValidationError::AllocationSumExceeded { allocated, maximum });
    }
    Ok(())
}

fn compare_allocations(
    left: &PartitionEscrowAllocation,
    right: &PartitionEscrowAllocation,
) -> Ordering {
    left.partition_id()
        .as_bytes()
        .cmp(right.partition_id().as_bytes())
        .then_with(|| {
            left.authority_id()
                .as_bytes()
                .cmp(right.authority_id().as_bytes())
        })
}

pub(super) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PartitionEscrowValidationError> {
    if value.is_empty()
        || value.len() > MAX_PARTITION_ESCROW_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(PartitionEscrowValidationError::InvalidIdentifier(field));
    }
    Ok(())
}

pub(super) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), PartitionEscrowValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PartitionEscrowValidationError::InvalidDigest(field));
    }
    Ok(())
}
