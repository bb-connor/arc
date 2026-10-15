//! Shared synthetic REC-0a vector fixtures for recovery unit tests.
use crate::ToolCallRequest;
use chio_security_types::recovery::RecoveryScopeV1;
use serde_json::Value;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn authority_fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?)
}

/// The vector request with its recovery `declassification_grant` removed.
/// Main's `ToolCallRequest.declassification_grant` is still the ordinary
/// `SignedDeclassificationGrant`, so this seed cannot carry the recovery grant
/// variant. Delete this removal and re-derive every seed digest when
/// `ToolCallRequest` adopts `SignedDisclosureGrant`.
pub(super) fn seed_wire() -> TestResult<Value> {
    let mut seed = authority_fixture()?["request"].clone();
    seed.as_object_mut()
        .ok_or("request fixture must be an object")?
        .remove("declassification_grant")
        .ok_or("request fixture must carry its recovery grant")?;
    Ok(seed)
}

pub(super) fn seed_request() -> TestResult<ToolCallRequest> {
    Ok(serde_json::from_value(seed_wire()?)?)
}

pub(super) fn action_scope() -> TestResult<RecoveryScopeV1> {
    Ok(serde_json::from_value(
        authority_fixture()?["action"]["scope"].clone(),
    )?)
}
