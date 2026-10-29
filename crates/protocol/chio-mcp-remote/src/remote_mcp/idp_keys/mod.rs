//! Identity-provider signing keys pinned to one provider record.
//!
//! Keys come only from the record's `jwks_url`, or from its inline `jwks`.
//! Token headers are admitted by [`crate::root_exchange::jws`] before any
//! key lookup. A fetched JWKS document is admitted only within
//! [`MAX_JWKS_DOCUMENT_BYTES`]; keys that fail the per-key checks are
//! dropped from the set. An unknown `kid` triggers at most one refresh, and
//! every fetch for one source is spaced by at least
//! [`RefreshPolicy::min_fetch_interval_secs`]. A key set older than
//! [`RefreshPolicy::scheduled_refresh_secs`] is refetched before use and
//! denies while it cannot be. After a refresh fails or is cancelled, no
//! key resolves until a later refresh succeeds and is recorded. Every change to the key set is signed by the
//! exchange key as a `chio.idp-key-snapshot.v1` and recorded before the set
//! is used. Time is the caller's `now`; nothing here reads a clock.
//! [`IdpKeySources`] is the root exchange's
//! [`IdpKeyLookup`](crate::root_exchange::IdpKeyLookup).

mod document;
mod fetch;
mod lookup;
mod source;
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

pub use document::{admit_jwks_document, JwksDocumentError};
pub use fetch::{ContractJwksFetcher, JwksFetchError, JwksFetcher};
pub use lookup::{IdpKeySources, IdpKeySourcesError};
pub use source::{
    IdpKeySourceError, KeyResolutionError, KeySnapshotSink, PinnedIdpKeys, RefreshPolicy,
    RefreshPolicyError, ResolvedIdpKey, SnapshotNotRecorded, SnapshotNotSigned,
    DEFAULT_MIN_FETCH_INTERVAL_SECS, DEFAULT_SCHEDULED_REFRESH_SECS,
};

/// Largest JWKS document admitted, in bytes.
pub const MAX_JWKS_DOCUMENT_BYTES: usize = 64 * 1024;

/// Smallest admitted RSA modulus, in bits.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Most keys one admitted key set may hold; the `chio.idp-key-snapshot.v1` bound.
pub const MAX_ADMITTED_KEYS: usize = 64;
