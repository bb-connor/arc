//! Numeric bounds and redacted store errors.

use super::*;

pub(super) fn canonical_digest(value: &impl Serialize) -> Result<String, FiscalStoreError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(canonical_error)
}

pub(super) fn canonical_error(error: impl std::fmt::Display) -> FiscalStoreError {
    invariant(format!("canonical fiscal encoding failed: {error}"))
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> FiscalStoreError {
    FiscalStoreError::Unavailable(error.to_string())
}

pub(super) fn map_owner_error(error: SqliteServingOwnerError) -> FiscalStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => FiscalStoreError::OutcomeUnknown(detail),
        other => FiscalStoreError::Unavailable(other.to_string()),
    }
}

pub(super) fn invariant(detail: impl Into<String>) -> FiscalStoreError {
    FiscalStoreError::Invariant(detail.into())
}

pub(super) fn sqlite_i64(value: u64, field: &str) -> Result<i64, FiscalStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite INTEGER")))
}

pub(super) fn read_u64(value: i64, field: &str) -> Result<u64, FiscalStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

pub(super) struct ImmutableArtifact<'a> {
    pub(super) table: &'a str,
    pub(super) id_column: &'a str,
    pub(super) id: &'a str,
    pub(super) digest_column: &'a str,
    pub(super) digest: &'a str,
    pub(super) json: &'a [u8],
    pub(super) mutation_kind: &'a str,
    pub(super) fence: &'a StoreMutationFence,
}

pub(super) struct ExactGenesis<'a> {
    pub(super) policy_json: &'a [u8],
    pub(super) authority_json: &'a [u8],
    pub(super) charter_json: &'a [u8],
    pub(super) readiness_json: &'a [u8],
    pub(super) registry_json: &'a [u8],
    pub(super) checkpoint_json: &'a [u8],
    pub(super) policy: &'a FiscalGenesisPolicy,
    pub(super) charter: &'a VerifiedFiscalCharter,
    pub(super) readiness: &'a VerifiedFiscalRuntimeReadiness,
    pub(super) checkpoint: &'a VerifiedFiscalContinuityCheckpoint,
}
