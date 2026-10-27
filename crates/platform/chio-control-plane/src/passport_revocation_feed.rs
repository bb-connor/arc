//! The published passport revocation feed.
//!
//! An operator publishes a signed epoch root over its passport revocation
//! oracle and bounded pages of the oracle's ordered leaves. A partner rebuilds
//! the tree from the leaves and accepts it only when its root equals the
//! signed root. The root is signed with the operator's trust-control
//! authority key, and its `issued_at_unix_ms` is the signing time, so the
//! partner measures freshness from the moment the operator attested the set.
//!
//! Every integer the feed publishes is at most [`MAX_JSON_SAFE_INTEGER`], so
//! a peer that parses JSON numbers as IEEE-754 doubles rebuilds the same
//! root.

use std::path::Path;

use chio_core::crypto::{Keypair, PublicKey};
use chio_credentials::PassportLifecycleState;
use chio_revocation_oracle::{
    Ed25519RootSigner, Ed25519RootVerifier, EpochRoot, PassportRevocationLeaf,
    PassportRevocationLeafKind, SignedEpochRoot, SqliteRevocationOracle,
};
use serde::{Deserialize, Serialize};

use crate::passport_revocation::passport_revocation_oracle_path;
use crate::passport_verifier::PassportStatusRegistry;

pub const PASSPORT_REVOCATION_ROOT_SCHEMA: &str = "chio.trust.passport-revocation-root.v1";

pub const PASSPORT_REVOCATION_LEAVES_SCHEMA: &str = "chio.trust.passport-revocation-leaves.v1";

/// Most leaves in one page.
pub const MAX_PASSPORT_REVOCATION_PAGE_LEAVES: usize = 256;

/// Largest serialized page, in bytes. The publisher fills a page below it and
/// a reader refuses a body above it.
pub const MAX_PASSPORT_REVOCATION_PAGE_BYTES: usize = 512 * 1024;

/// Largest integer every JSON peer represents exactly: 2^53 - 1.
pub const MAX_JSON_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Room kept below [`MAX_PASSPORT_REVOCATION_PAGE_BYTES`] for the page
/// envelope around its leaves.
const PAGE_ENVELOPE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PassportRevocationFeedError {
    #[error("passport revocation oracle unavailable: {0}")]
    OracleUnavailable(String),
    #[error("passport lifecycle registry unavailable: {0}")]
    RegistryUnavailable(String),
    #[error(
        "passport lifecycle registry holds {revoked} revoked passports but the revocation oracle holds {passport_leaves} passport leaves"
    )]
    OracleBehindRegistry { revoked: u64, passport_leaves: u64 },
    #[error("authority clock reads {now_unix_ms}, before the revocation oracle root at {root_issued_at_unix_ms}")]
    ClockBehindOracle {
        now_unix_ms: u64,
        root_issued_at_unix_ms: u64,
    },
    #[error("passport revocation root field `{0}` exceeds the JSON-safe integer range")]
    BeyondJsonPrecision(&'static str),
    #[error("passport revocation root signing failed: {0}")]
    Signing(String),
    #[error("unsupported passport revocation document schema `{0}`")]
    UnsupportedSchema(String),
    #[error("passport revocation leaf cursor {0} is out of range")]
    CursorOutOfRange(u64),
    #[error("passport revocation leaf {seq} cannot be published: {reason}")]
    UnpublishableLeaf { seq: u64, reason: String },
}

/// The published signed epoch root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportRevocationRootDocument {
    pub schema: String,
    pub signed_root: SignedEpochRoot,
}

impl PassportRevocationRootDocument {
    #[must_use]
    pub fn new(signed_root: SignedEpochRoot) -> Self {
        Self {
            schema: PASSPORT_REVOCATION_ROOT_SCHEMA.to_owned(),
            signed_root,
        }
    }

    /// The carried signed root, refusing a document of any other schema.
    pub fn into_signed_root(self) -> Result<SignedEpochRoot, PassportRevocationFeedError> {
        if self.schema != PASSPORT_REVOCATION_ROOT_SCHEMA {
            return Err(PassportRevocationFeedError::UnsupportedSchema(self.schema));
        }
        Ok(self.signed_root)
    }
}

/// The leaves with a sequence number above `after`, in sequence order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportRevocationLeavesPage {
    pub schema: String,
    pub after: u64,
    pub leaves: Vec<PassportRevocationLeaf>,
}

impl PassportRevocationLeavesPage {
    /// The carried leaves, refusing a page of any other schema.
    pub fn into_leaves(self) -> Result<Vec<PassportRevocationLeaf>, PassportRevocationFeedError> {
        if self.schema != PASSPORT_REVOCATION_LEAVES_SCHEMA {
            return Err(PassportRevocationFeedError::UnsupportedSchema(self.schema));
        }
        Ok(self.leaves)
    }
}

/// The signer id carried by a root signed with `key`.
#[must_use]
pub fn passport_revocation_root_signer_id(key: &PublicKey) -> String {
    key.to_hex()
}

/// The verifier that accepts only roots signed with the pinned `key`.
#[must_use]
pub fn passport_revocation_root_verifier(key: &PublicKey) -> Ed25519RootVerifier {
    Ed25519RootVerifier::new(passport_revocation_root_signer_id(key), key.clone())
}

/// Refuses when the oracle file beside `registry` is no longer a regular
/// file. A lost oracle is lost revocation state, never an empty set.
fn require_oracle_file(registry: &Path) -> Result<(), PassportRevocationFeedError> {
    let unavailable = |error: String| PassportRevocationFeedError::OracleUnavailable(error);
    let path = passport_revocation_oracle_path(registry)
        .map_err(|error| unavailable(error.to_string()))?;
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|error| unavailable(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(unavailable(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

/// Refuses when the registry at `registry` records more revoked passports
/// than the oracle holds passport leaves. Every revocation writes the oracle
/// before the registry, so the oracle can only lead.
fn require_oracle_covers_registry(
    oracle: &SqliteRevocationOracle,
    registry: &Path,
) -> Result<(), PassportRevocationFeedError> {
    let lifecycle = PassportStatusRegistry::load(registry)
        .map_err(|error| PassportRevocationFeedError::RegistryUnavailable(error.to_string()))?;
    let revoked = lifecycle
        .passports
        .values()
        .filter(|record| record.status == PassportLifecycleState::Revoked)
        .count();
    let revoked = u64::try_from(revoked).unwrap_or(u64::MAX);
    let passport_leaves = oracle
        .leaf_count_with_nonce(PassportRevocationLeafKind::Passport.epoch_nonce())
        .map_err(|error| PassportRevocationFeedError::OracleUnavailable(error.to_string()))?;
    if revoked > passport_leaves {
        return Err(PassportRevocationFeedError::OracleBehindRegistry {
            revoked,
            passport_leaves,
        });
    }
    Ok(())
}

fn json_safe(field: &'static str, value: u64) -> Result<(), PassportRevocationFeedError> {
    if value > MAX_JSON_SAFE_INTEGER {
        return Err(PassportRevocationFeedError::BeyondJsonPrecision(field));
    }
    Ok(())
}

/// Signs the current root of `oracle`, the oracle beside `registry`, at
/// `now_unix_ms`.
pub fn sign_passport_revocation_root(
    oracle: &SqliteRevocationOracle,
    registry: &Path,
    authority: Keypair,
    now_unix_ms: u64,
) -> Result<SignedEpochRoot, PassportRevocationFeedError> {
    require_oracle_file(registry)?;
    let root = oracle
        .current_epoch_root()
        .map_err(|error| PassportRevocationFeedError::OracleUnavailable(error.to_string()))?;
    require_oracle_covers_registry(oracle, registry)?;
    if now_unix_ms < root.issued_at_unix_ms {
        return Err(PassportRevocationFeedError::ClockBehindOracle {
            now_unix_ms,
            root_issued_at_unix_ms: root.issued_at_unix_ms,
        });
    }
    json_safe("epoch", root.epoch)?;
    json_safe(
        "leaf_count",
        u64::try_from(root.leaf_count).unwrap_or(u64::MAX),
    )?;
    json_safe("issued_at_unix_ms", now_unix_ms)?;
    let attested = EpochRoot {
        issued_at_unix_ms: now_unix_ms,
        ..root
    };
    let signer = Ed25519RootSigner::new(
        passport_revocation_root_signer_id(&authority.public_key()),
        authority,
    );
    SignedEpochRoot::sign(attested, &signer)
        .map_err(|error| PassportRevocationFeedError::Signing(error.to_string()))
}

/// The page of leaves after `after` from `oracle`, the oracle beside
/// `registry`, filled up to [`MAX_PASSPORT_REVOCATION_PAGE_LEAVES`] leaves and
/// below [`MAX_PASSPORT_REVOCATION_PAGE_BYTES`].
pub fn passport_revocation_leaves_page(
    oracle: &SqliteRevocationOracle,
    registry: &Path,
    after: u64,
) -> Result<PassportRevocationLeavesPage, PassportRevocationFeedError> {
    if after > MAX_JSON_SAFE_INTEGER {
        return Err(PassportRevocationFeedError::CursorOutOfRange(after));
    }
    require_oracle_file(registry)?;
    let stored = oracle
        .leaves_after(after, MAX_PASSPORT_REVOCATION_PAGE_LEAVES)
        .map_err(|error| PassportRevocationFeedError::OracleUnavailable(error.to_string()))?;
    let budget = MAX_PASSPORT_REVOCATION_PAGE_BYTES - PAGE_ENVELOPE_BYTES;
    let mut used = 0_usize;
    let mut leaves = Vec::with_capacity(stored.len());
    for leaf in &stored {
        let published = PassportRevocationLeaf::from_oracle_leaf(leaf).map_err(|error| {
            PassportRevocationFeedError::UnpublishableLeaf {
                seq: leaf.seq,
                reason: error.to_string(),
            }
        })?;
        if published.seq > MAX_JSON_SAFE_INTEGER {
            return Err(PassportRevocationFeedError::UnpublishableLeaf {
                seq: published.seq,
                reason: "sequence number exceeds the JSON-safe integer range".to_owned(),
            });
        }
        let bytes = serde_json::to_vec(&published)
            .map_err(|error| PassportRevocationFeedError::UnpublishableLeaf {
                seq: published.seq,
                reason: error.to_string(),
            })?
            .len()
            .saturating_add(1);
        if used.saturating_add(bytes) > budget {
            if leaves.is_empty() {
                return Err(PassportRevocationFeedError::UnpublishableLeaf {
                    seq: published.seq,
                    reason: format!(
                        "leaf exceeds the {MAX_PASSPORT_REVOCATION_PAGE_BYTES}-byte page"
                    ),
                });
            }
            break;
        }
        used = used.saturating_add(bytes);
        leaves.push(published);
    }
    Ok(PassportRevocationLeavesPage {
        schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
        after,
        leaves,
    })
}

#[cfg(test)]
#[path = "passport_revocation_feed_tests.rs"]
mod tests;
