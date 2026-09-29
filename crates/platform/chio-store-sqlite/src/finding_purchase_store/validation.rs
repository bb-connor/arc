use super::*;

pub(super) fn verify_stored_digest(
    bytes: &[u8],
    expected_hex: &str,
    what: &str,
) -> Result<(), FindingPurchaseStoreError> {
    if sha256_hex(bytes) == expected_hex {
        Ok(())
    } else {
        Err(invariant(format!("{what} digest is invalid")))
    }
}

pub(super) fn require_terminal_record(
    bytes: &[u8],
    expected_hex: &str,
) -> Result<(), FindingPurchaseStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_TERMINAL_RECORD_BYTES {
        return Err(invariant("terminal record byte length is out of bounds"));
    }
    if sha256_hex(bytes) != expected_hex {
        return Err(FindingPurchaseStoreError::Conflict(
            "terminal record bytes do not match the claimed digest".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn require_hex64(
    value: &str,
    field: &'static str,
) -> Result<(), FindingPurchaseStoreError> {
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

pub(super) fn require_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), FindingPurchaseStoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

pub(super) fn require_evm_payout_destination(value: &str) -> Result<(), FindingPurchaseStoreError> {
    validate_evm_payout_destination(value)
        .map_err(|_| invariant("payout destination is not a valid EVM address"))
}

pub(super) fn require_currency(currency: &str) -> Result<(), FindingPurchaseStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

pub(super) fn require_trusted_time(
    value: u64,
    field: &'static str,
) -> Result<(), FindingPurchaseStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be nonzero")));
    }
    Ok(())
}

pub(super) fn sqlite_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, FindingPurchaseStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

pub(super) fn stored_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, FindingPurchaseStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

pub(super) fn stored_slot_index(value: i64) -> Result<u8, FindingPurchaseStoreError> {
    u8::try_from(value)
        .ok()
        .filter(|index| *index < PAYOUT_DESTINATION_SLOTS)
        .ok_or_else(|| invariant("stored payout slot index is out of range"))
}

pub(super) fn invariant(detail: impl Into<String>) -> FindingPurchaseStoreError {
    FindingPurchaseStoreError::Invariant(detail.into())
}

pub(super) fn admission_error(error: AdmissionOperationStoreError) -> FindingPurchaseStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingPurchaseStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingPurchaseStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingPurchaseStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingPurchaseStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingPurchaseStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> FindingPurchaseStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingPurchaseStoreError::Unavailable(other.to_string()),
    }
}
