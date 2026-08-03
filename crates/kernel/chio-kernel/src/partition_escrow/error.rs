use chio_core_types::partition_escrow::PartitionEscrowValidationError;

use crate::budget_store::BudgetStoreError;

#[derive(Debug, thiserror::Error)]
pub enum PartitionEscrowRegistryError {
    #[error(transparent)]
    Allocation(#[from] PartitionEscrowValidationError),
    #[error(transparent)]
    Budget(#[from] BudgetStoreError),
    #[error("partition escrow registry requires at least one allocation entry")]
    EmptyRegistry,
    #[error("partition escrow registry exceeds the bounded quota count")]
    RegistryTooLarge,
    #[error("partition escrow registry has multiple allocation sets for one logical quota key")]
    EquivocatingAllocationSet,
    #[error("partition escrow registry is missing the exact allocation set for a quota authority")]
    MissingAllocationSet,
    #[error("partition escrow admission quota count is empty or exceeds the bounded maximum")]
    InvalidAdmissionQuotaCount,
    #[error("partition escrow admission repeats one quota authority or quota descriptor")]
    DuplicateAdmissionQuota,
    #[error("partition escrow admission evidence changed its schema")]
    InvalidEvidenceSchema,
    #[error("partition escrow admission evidence changed its runtime configuration")]
    RuntimeEvidenceMismatch,
    #[error("partition escrow admission evidence changed its configured runtime identity")]
    RegistryIdentityMismatch,
    #[error("partition escrow admission evidence changed its verification time")]
    VerificationTimeMismatch,
    #[error("partition escrow admission evidence changed an ordered quota or allocation")]
    AdmissionEvidenceMismatch,
    #[error("partition escrow registry identifier `{0}` is invalid")]
    InvalidIdentifier(&'static str),
    #[error("partition escrow registry implementation version must be positive")]
    InvalidImplementationVersion,
    #[error("partition escrow registry digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("partition escrow registry canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("partition escrow source verification failed: {0}")]
    SourceVerification(String),
    #[error("partition escrow certificate does not match the verified source: {0}")]
    SourceBindingMismatch(&'static str),
    #[error("partition escrow verified source is not fresh for this admission")]
    SourceNotFresh,
    #[error("partition escrow admission does not match the configured durable store binding")]
    DurableStoreBindingMismatch,
    #[error("partition escrow admission evidence digest changed")]
    EvidenceDigestMismatch,
    #[error("partition escrow admission evidence envelope is invalid: {0}")]
    InvalidEvidenceEnvelope(String),
    #[error("partition escrow admission evidence envelope is not canonical JSON")]
    NonCanonicalEvidenceEnvelope,
}
