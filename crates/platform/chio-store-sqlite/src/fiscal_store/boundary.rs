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
