//! Response commitments share these exact versioned domain bytes across the
//! planner, kernel and receipt verifier; spec/fixtures pins them independently.

pub const RESPONSE_AFFECTED_SET_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
pub const RESPONSE_EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";
pub const RESPONSE_REQUEST_ID_DOMAIN: &[u8] = b"chio.response-request.v1\0";
pub const RESPONSE_TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-transition.v1\0";

/// Active-response authority protocol identity reported by the health check.
/// It names the protocol, never a signed artifact.
pub const ACTIVE_RESPONSE_AUTHORITY_PROTOCOL: &str = "chio.active-response-policy-authority.v1";
/// Signing-wrapper schema id of an active-response authority request.
pub const ACTIVE_RESPONSE_AUTHORITY_REQUEST_SCHEMA: &str =
    "chio.active-response-policy-authority-request.v1";
/// Signing-wrapper schema id of an active-response authority response.
pub const ACTIVE_RESPONSE_AUTHORITY_RESPONSE_SCHEMA: &str =
    "chio.active-response-policy-authority-response.v1";
