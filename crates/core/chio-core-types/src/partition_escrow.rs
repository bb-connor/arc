//! Signed partition-escrow allocation sets.
//!
//! The artifact module defines canonical signed certificate and allocation
//! contracts. Core validation proves their cryptographic structure and local
//! allocation shape only. A kernel profile adapter must bind the certificate to
//! a live authenticated source before it can become admission authority.

mod artifact;
mod commitment;
mod error;
mod validation;

pub use artifact::{
    PartitionEscrowAllocation, PartitionEscrowAllocationPlan, PartitionEscrowAllocationPlanBinding,
    PartitionEscrowAllocationSetBody, PartitionEscrowQuota, SignedPartitionEscrowAllocationSet,
    MAX_PARTITION_ESCROW_ALLOCATIONS, MAX_PARTITION_ESCROW_IDENTIFIER_BYTES,
    PARTITION_ESCROW_ALLOCATION_PLAN_DIGEST_DOMAIN, PARTITION_ESCROW_ALLOCATION_SET_DIGEST_DOMAIN,
    PARTITION_ESCROW_ALLOCATION_SET_SCHEMA, PARTITION_ESCROW_ALLOCATION_SIGNATURE_DOMAIN,
    PARTITION_ESCROW_QUOTA_DESCRIPTOR_DOMAIN, PARTITION_ESCROW_QUOTA_KEY_DOMAIN,
};
pub use commitment::{
    verify_partition_escrow_quota_commitment, PartitionEscrowQuotaCommitmentBody,
    PartitionEscrowQuotaSourceBinding, SignedPartitionEscrowQuotaCommitment,
    VerifiedPartitionEscrowQuotaCertificate, PARTITION_ESCROW_QUOTA_AUTHORITY_BINDING_DOMAIN,
    PARTITION_ESCROW_QUOTA_COMMITMENT_DIGEST_DOMAIN, PARTITION_ESCROW_QUOTA_COMMITMENT_SCHEMA,
    PARTITION_ESCROW_QUOTA_COMMITMENT_SIGNATURE_DOMAIN,
};
pub use error::PartitionEscrowValidationError;
pub use validation::{
    verify_partition_escrow_allocation_set, verify_partition_escrow_allocation_set_structure,
    PartitionEscrowAllocationVerificationContext, StructurallyVerifiedPartitionEscrowAllocation,
    VerifiedPartitionEscrowAllocation,
};

#[cfg(test)]
mod tests;
