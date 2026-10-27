//! Typed reads of JWT claims.

use serde_json::{Map, Value};

use super::error::RootExchangeError;

pub(super) fn string<'a>(
    claims: &'a Map<String, Value>,
    name: &'static str,
) -> Result<Option<&'a str>, RootExchangeError> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && !value.contains('\0') => Ok(Some(value)),
        Some(_) => Err(RootExchangeError::ClaimInvalid(name)),
    }
}

pub(super) fn required_string<'a>(
    claims: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a str, RootExchangeError> {
    string(claims, name)?.ok_or(RootExchangeError::ClaimMissing(name))
}

pub(super) fn seconds(
    claims: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<u64>, RootExchangeError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(RootExchangeError::ClaimInvalid(name)),
    }
}

pub(super) fn required_seconds(
    claims: &Map<String, Value>,
    name: &'static str,
) -> Result<u64, RootExchangeError> {
    seconds(claims, name)?.ok_or(RootExchangeError::ClaimMissing(name))
}

/// `aud` equals `expected`: a single string, or a one-element array.
pub(super) fn audience_is(claims: &Map<String, Value>, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(audience)) => audience == expected,
        Some(Value::Array(audiences)) => {
            matches!(audiences.as_slice(), [Value::String(audience)] if audience == expected)
        }
        _ => false,
    }
}

/// Space-delimited `scope` values, deduplicated in order.
pub(super) fn scope_values(claims: &Map<String, Value>) -> Result<Vec<String>, RootExchangeError> {
    let Some(scope) = string(claims, "scope")? else {
        return Ok(Vec::new());
    };
    let mut values: Vec<String> = Vec::new();
    for value in scope.split(' ').filter(|value| !value.is_empty()) {
        if !values.iter().any(|seen| seen == value) {
            values.push(value.to_owned());
        }
    }
    Ok(values)
}
