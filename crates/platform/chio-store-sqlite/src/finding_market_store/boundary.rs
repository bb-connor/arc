//! Numeric bounds and redacted store errors.

use super::*;

pub(super) fn require_hex64(
    value: &str,
    field: &'static str,
) -> Result<(), FindingMarketStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

pub(super) fn require_non_empty(
    value: &str,
    field: &'static str,
) -> Result<(), FindingMarketStoreError> {
    if value.is_empty() || value.len() > 512 {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

pub(super) fn require_currency(currency: &str) -> Result<(), FindingMarketStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

pub(super) fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingMarketStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

pub(super) fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingMarketStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

pub(super) fn invariant(detail: impl Into<String>) -> FindingMarketStoreError {
    FindingMarketStoreError::Invariant(detail.into())
}

pub(super) fn admission_error(error: AdmissionOperationStoreError) -> FindingMarketStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingMarketStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingMarketStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingMarketStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingMarketStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingMarketStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> FindingMarketStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingMarketStoreError::Unavailable(other.to_string()),
    }
}
