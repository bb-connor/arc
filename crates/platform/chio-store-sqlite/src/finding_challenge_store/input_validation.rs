//! Validate finite input bounds before entering durable transitions.

use super::*;

pub(super) fn list_limit() -> Result<i64, FindingChallengeStoreError> {
    sqlite_i64(u64::try_from(MAX_LIST_ROWS).unwrap_or(u64::MAX), "limit")
}

pub(super) fn require_hex64(
    value: &str,
    field: &'static str,
) -> Result<(), FindingChallengeStoreError> {
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

pub(super) fn require_outcome_envelope(
    outcome_envelope_sha256: &str,
    outcome_envelope_json: &[u8],
) -> Result<(), FindingChallengeStoreError> {
    require_hex64(outcome_envelope_sha256, "outcome_envelope_sha256")?;
    if outcome_envelope_json.is_empty() || outcome_envelope_json.len() > MAX_OUTCOME_ENVELOPE_BYTES
    {
        return Err(invariant("outcome envelope byte length is out of bounds"));
    }
    if sha256_hex(outcome_envelope_json) != outcome_envelope_sha256 {
        return Err(invariant(
            "outcome envelope bytes do not match their recorded digest",
        ));
    }
    Ok(())
}

pub(super) fn require_outcome_allocation_binding(
    outcome_envelope_json: &[u8],
    allocation_id: &str,
) -> Result<(), FindingChallengeStoreError> {
    let envelope: serde_json::Value =
        chio_core::canonical::UntrustedJsonText::from_wire(outcome_envelope_json, 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())
            .map_err(FindingChallengeStoreError::from)?;
    let retained_allocation_id = envelope
        .get("body")
        .and_then(|body| body.get("backing_allocation_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invariant("outcome envelope omits its backing allocation"))?;
    require_hex64(retained_allocation_id, "outcome.backing_allocation_id")?;
    if retained_allocation_id != allocation_id {
        return Err(FindingChallengeStoreError::Conflict(
            "exposure fence allocation does not match the retained outcome".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn require_finalizing_authorization(
    authorization: &FindingFinalizingAuthorizationInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_hex64(authorization.liability_key, "liability_key")?;
    require_hex64(authorization.authorization_sha256, "authorization_sha256")?;
    require_trusted_time(authorization.recorded_at, "recorded_at")?;
    if authorization.authorization_json.is_empty()
        || authorization.authorization_json.len() > MAX_FINALIZING_AUTHORIZATION_BYTES
    {
        return Err(invariant(
            "finalizing authorization byte length is out of bounds",
        ));
    }
    if sha256_hex(authorization.authorization_json) != authorization.authorization_sha256 {
        return Err(invariant(
            "finalizing authorization bytes do not match their digest",
        ));
    }
    Ok(())
}

pub(super) fn require_chain_hash(
    value: &str,
    field: &'static str,
) -> Result<(), FindingChallengeStoreError> {
    if value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not a 0x-prefixed 32-byte lowercase hash"
    )))
}

pub(super) fn require_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), FindingChallengeStoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

pub(super) fn require_currency(currency: &str) -> Result<(), FindingChallengeStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

pub(super) fn require_trusted_time(
    value: u64,
    field: &'static str,
) -> Result<(), FindingChallengeStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be nonzero")));
    }
    Ok(())
}

pub(super) fn sqlite_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, FindingChallengeStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

pub(super) fn stored_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, FindingChallengeStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

pub(super) fn stored_flag(
    value: i64,
    field: &'static str,
) -> Result<bool, FindingChallengeStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invariant(format!("{field} is not a boolean flag"))),
    }
}

pub(super) fn invariant(detail: impl Into<String>) -> FindingChallengeStoreError {
    FindingChallengeStoreError::Invariant(detail.into())
}

pub(super) fn admission_error(error: AdmissionOperationStoreError) -> FindingChallengeStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingChallengeStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingChallengeStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingChallengeStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingChallengeStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingChallengeStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

/// Map a purchase-store failure raised inside a shared transaction. The
/// sales block is part of the upheld transaction, so its failures are the
/// challenge lane's failures.
pub(super) fn purchase_error(error: FindingPurchaseStoreError) -> FindingChallengeStoreError {
    match error {
        FindingPurchaseStoreError::Fenced => FindingChallengeStoreError::Fenced,
        FindingPurchaseStoreError::NotFound => FindingChallengeStoreError::NotFound,
        FindingPurchaseStoreError::Unavailable(detail) => {
            FindingChallengeStoreError::Unavailable(detail)
        }
        FindingPurchaseStoreError::OutcomeUnknown(detail) => {
            FindingChallengeStoreError::OutcomeUnknown(detail)
        }
        FindingPurchaseStoreError::Invariant(detail) => {
            FindingChallengeStoreError::Invariant(detail)
        }
        other => FindingChallengeStoreError::Conflict(other.to_string()),
    }
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> FindingChallengeStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingChallengeStoreError::Unavailable(other.to_string()),
    }
}
