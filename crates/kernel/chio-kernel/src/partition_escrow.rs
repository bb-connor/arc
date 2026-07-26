//! Immutable runtime registry for partition-escrow allocation contracts.
//!
//! Each entry binds one kernel-verified quota authority to one signed
//! allocation set. Source signer, source digest, source expiry, root identity,
//! epoch, and allocation-set digest are pinned per quota. The registry has no
//! replacement operation in v1.

mod error;
mod evidence;
mod registry;
mod source;

pub use error::PartitionEscrowRegistryError;
pub use evidence::{
    PartitionEscrowAdmissionEvidence, PartitionEscrowAdmissionQuotaEvidence,
    PartitionEscrowDurableStoreEvidence, PartitionEscrowResolverRuntimeEvidence,
    PARTITION_ESCROW_ADMISSION_EVIDENCE_SCHEMA,
};
pub use registry::{
    partition_escrow_counter_namespace_digest, AdmissionCapableEscrowQuota,
    PartitionEscrowAdmission, PartitionEscrowRegistry, PartitionEscrowRegistryEntryInput,
    PartitionEscrowRegistryInput, PARTITION_ESCROW_REGISTRY_SCHEMA,
};

#[cfg(test)]
pub(crate) use source::{verify_grant_partition_escrow_source, VerifiedPartitionEscrowQuotaSource};

#[cfg(test)]
mod tests;
