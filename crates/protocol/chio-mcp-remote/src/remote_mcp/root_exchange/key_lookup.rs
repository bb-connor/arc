//! The identity-provider key source the exchange verifies assertions against.

use async_trait::async_trait;
use chio_core::root_authority::{EnterpriseProviderIdentity, Jwk, JwsAlgorithm, Sha256Digest};

use super::error::RootExchangeError;

/// A key for one assertion and the key snapshot it was taken from.
#[derive(Debug, Clone)]
pub struct IdpKey {
    pub jwk: Jwk,
    /// Digest of the `chio.idp-key-snapshot.v1` in force for `jwk`.
    pub snapshot_digest: Sha256Digest,
}

/// Resolves `kid` for `alg` among the keys pinned for a provider record at
/// `now` (Unix seconds). Keys come only from the record's own key source.
/// An unknown `kid`, an unreachable or invalid key source, or a key that
/// does not admit `alg` is an error; no fallback key is ever returned.
/// `kid` is an opaque lookup key: it is NUL-free and at most 128 characters
/// but otherwise unrestricted, so it is never interpolated into a path, URL
/// or query.
#[async_trait]
pub trait IdpKeyLookup: Send + Sync {
    async fn resolve(
        &self,
        provider: &EnterpriseProviderIdentity,
        kid: &str,
        alg: JwsAlgorithm,
        now: u64,
    ) -> Result<IdpKey, RootExchangeError>;
}
