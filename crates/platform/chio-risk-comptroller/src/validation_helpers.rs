use super::*;

pub(super) fn require_non_empty(
    value: &str,
    field: &'static str,
) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(claim_failed(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

pub(super) fn optional_non_empty<'a>(
    value: Option<&'a String>,
    field: &'static str,
) -> Result<Option<&'a str>, TransactionPassportError> {
    match value {
        Some(value) => {
            require_non_empty(value, field)?;
            Ok(Some(value.as_str()))
        }
        None => Ok(None),
    }
}

pub(super) fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| claim_failed(format!("invalid risk timestamp: {field}")))
}

pub(super) fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::RiskComptrollerClaimFailed(message.into())
}
