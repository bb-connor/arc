//! Scoped trust-control caller credentials and pinned cluster peer keys.
//!
//! A caller credential names one deployment, a closed set of scopes and a
//! tenant authority. Its secret is held only as a SHA-256 digest and compared
//! in constant time. A cluster peer authenticates with an Ed25519 signature
//! from the key pinned for its node id; no shared secret authenticates a peer.

mod access;
mod caller;
mod peer;
mod peer_nonces;
mod scope;

pub use access::{AccessConfigDocument, TrustAccess, TrustAccessConfig, TrustAccessError};
pub use caller::{
    AuthenticatedCaller, CallerAuthError, CallerCredentials, CredentialKind, TenantAuthority,
};
pub use peer::{
    sign_cluster_peer_request, AuthenticatedPeer, ClusterNodeIdentity, ClusterPeer,
    ClusterPeerPins, PeerAddressing, PeerAuthError, PeerRequestSignature, PeerRequestTarget,
    CLUSTER_AUTH_BODY_SHA256_HEADER, CLUSTER_AUTH_NONCE_HEADER, CLUSTER_PEER_SIGNATURE_SCHEME,
};
pub use peer_nonces::{
    PeerNonceCache, CLUSTER_PEER_NONCE_CACHE_CAPACITY, CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS,
    CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS,
};
pub use scope::Scope;

fn is_lowercase_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Non-empty, at most `max_bytes`, without surrounding whitespace or control
/// characters.
fn is_clean_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
pub(crate) mod tests;
