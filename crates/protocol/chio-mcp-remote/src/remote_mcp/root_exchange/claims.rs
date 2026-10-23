//! Typed reads of JWT claims.

use chio_core::root_authority::{EnterpriseProviderIdentity, Uri};
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

/// Some `aud` value, a string or an array of strings, is in `allowed`.
pub(super) fn audience_in(claims: &Map<String, Value>, allowed: &[Uri]) -> bool {
    let listed = |value: &Value| {
        value
            .as_str()
            .is_some_and(|audience| allowed.iter().any(|uri| uri.as_str() == audience))
    };
    match claims.get("aud") {
        Some(Value::Array(audiences)) => audiences.iter().any(listed),
        Some(value) => listed(value),
        None => false,
    }
}

/// Read the claim `name` as the principal or tenant value.
pub(super) fn mapped_claim(
    claims: &Map<String, Value>,
    name: &str,
    which: &'static str,
) -> Result<String, RootExchangeError> {
    match claims.get(name) {
        Some(Value::String(value)) if !value.is_empty() && !value.contains('\0') => {
            Ok(value.clone())
        }
        Some(_) => Err(RootExchangeError::ClaimInvalid(which)),
        None => Err(RootExchangeError::ClaimMissing(which)),
    }
}

/// The principal and tenant the record's `subject_mapping` names.
pub(super) fn mapped_identity(
    claims: &Map<String, Value>,
    record: &EnterpriseProviderIdentity,
) -> Result<(String, String), RootExchangeError> {
    Ok((
        mapped_claim(
            claims,
            record.subject_mapping.principal_source.as_str(),
            "principal",
        )?,
        mapped_claim(
            claims,
            record.subject_mapping.tenant_id_field.as_str(),
            "tenant",
        )?,
    ))
}

/// The time rules of a bearer assertion at `now` under `skew`: `exp` and
/// `iat` are required, `now < exp + skew`, `iat <= now + skew`, `nbf <= now +
/// skew` and `iat < exp`. Returns `(iat, exp)`.
pub(super) fn check_times(
    claims: &Map<String, Value>,
    now: u64,
    skew: u64,
) -> Result<(u64, u64), RootExchangeError> {
    let exp = required_seconds(claims, "exp")?;
    let iat = required_seconds(claims, "iat")?;
    if now >= exp.saturating_add(skew) {
        return Err(RootExchangeError::AssertionExpired);
    }
    if iat > now.saturating_add(skew) {
        return Err(RootExchangeError::AssertionIssuedInFuture);
    }
    if seconds(claims, "nbf")?.is_some_and(|nbf| nbf > now.saturating_add(skew)) {
        return Err(RootExchangeError::AssertionNotYetValid);
    }
    if exp <= iat {
        return Err(RootExchangeError::ClaimInvalid("exp"));
    }
    Ok((iat, exp))
}

/// Space-delimited `scope` values, deduplicated in order.
pub(super) fn scope_values(claims: &Map<String, Value>) -> Result<Vec<String>, RootExchangeError> {
    let mut values = Vec::new();
    push_space_delimited(claims, "scope", &mut values)?;
    Ok(values)
}

/// Append the space-delimited scope tokens of claim `name` to `values`,
/// skipping values already present.
pub(super) fn push_space_delimited(
    claims: &Map<String, Value>,
    name: &'static str,
    values: &mut Vec<String>,
) -> Result<(), RootExchangeError> {
    let Some(scope) = string(claims, name)? else {
        return Ok(());
    };
    for value in scope.split(' ').filter(|value| !value.is_empty()) {
        push_scope_token(value, name, values)?;
    }
    Ok(())
}

/// Append one scope token of claim `name` to `values` unless present.
pub(super) fn push_scope_token(
    value: &str,
    name: &'static str,
    values: &mut Vec<String>,
) -> Result<(), RootExchangeError> {
    if !is_scope_token(value) {
        return Err(RootExchangeError::ClaimInvalid(name));
    }
    if !values.iter().any(|seen| seen == value) {
        values.push(value.to_owned());
    }
    Ok(())
}

/// Whether `token` is an RFC 6749 section 3.3 `scope-token`: one or more of
/// `%x21 / %x23-5B / %x5D-7E`.
pub(super) fn is_scope_token(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}
