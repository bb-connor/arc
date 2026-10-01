//! Invocation compatibility negotiated once during MCP initialization.
//!
//! These declarations do not grant authority. Signed artifacts and installed
//! kernel authorities remain responsible for every invocation decision.

use chio_core::capability::features::{
    CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, CUMULATIVE_APPROVAL_BUDGET,
    GOVERNED_ACTIVE_RESPONSE_PLAN, OPAQUE_SUPPLEMENTAL_AUTHORIZATION, THRESHOLD_GOVERNED_APPROVALS,
};
use serde_json::Value;

use crate::AdapterError;

pub const CHIO_AUTHORIZATION_CAPABILITY_KEY: &str = "chioAuthorization";

/// The edge's semantic support ceiling, not a statement of installed custody.
#[must_use]
pub fn authorization_capabilities() -> CapabilityNegotiation {
    let mut profile = CapabilityNegotiation::v1_default();
    for feature in [
        AGGREGATE_INVOCATION_BUDGET,
        CUMULATIVE_APPROVAL_BUDGET,
        THRESHOLD_GOVERNED_APPROVALS,
        GOVERNED_ACTIVE_RESPONSE_PLAN,
        OPAQUE_SUPPLEMENTAL_AUTHORIZATION,
    ] {
        profile.features.insert(feature.to_string(), true);
    }
    profile
}

/// Parse only the initialize handshake, rejecting malformed declarations.
/// Callers must persist the result with the authenticated session and must not
/// call this function on tool-call metadata to upgrade an existing session.
pub fn negotiate_authorization_capabilities(
    params: &Value,
) -> Result<CapabilityNegotiation, AdapterError> {
    let invalid = |message: &str| AdapterError::ParseError(message.to_string());
    let Some(capabilities) = params.get("capabilities") else {
        return Ok(CapabilityNegotiation::v1_default());
    };
    let capabilities = capabilities
        .as_object()
        .ok_or_else(|| invalid("MCP initialize capabilities must be an object"))?;
    let Some(experimental) = capabilities.get("experimental") else {
        return Ok(CapabilityNegotiation::v1_default());
    };
    let experimental = experimental
        .as_object()
        .ok_or_else(|| invalid("MCP initialize experimental capabilities must be an object"))?;
    let Some(profile) = experimental.get(CHIO_AUTHORIZATION_CAPABILITY_KEY) else {
        return Ok(CapabilityNegotiation::v1_default());
    };
    let peer: CapabilityNegotiation = serde_json::from_value(profile.clone())
        .map_err(|error| invalid(&format!("invalid MCP authorization capabilities: {error}")))?;
    authorization_capabilities()
        .negotiated_with(&peer)
        .map_err(|error| invalid(&format!("invalid MCP authorization capabilities: {error}")))
}
