//! Response commitments share these exact versioned domain bytes across the
//! planner, kernel and receipt verifier. Compatibility fixtures stay independent.

pub const RESPONSE_AFFECTED_SET_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
pub const RESPONSE_EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";
pub const RESPONSE_REQUEST_ID_DOMAIN: &[u8] = b"chio.response-request.v1\0";
pub const RESPONSE_TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-transition.v1\0";
