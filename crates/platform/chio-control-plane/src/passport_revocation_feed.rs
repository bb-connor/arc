//! The published passport revocation feed.
//!
//! An operator publishes a signed epoch root over its passport revocation
//! oracle and bounded pages of the oracle's ordered leaves. A partner rebuilds
//! the tree from the leaves and accepts it only when its root equals the
//! signed root. The root is signed with the operator's trust-control
//! authority key, and its `issued_at_unix_ms` is the signing time, so the
//! partner measures freshness from the moment the operator attested the set.

use std::path::Path;

use chio_core::crypto::{Keypair, PublicKey};
use chio_revocation_oracle::{
    Ed25519RootSigner, Ed25519RootVerifier, EpochRoot, InMemoryRevocationOracle, RevocationOracle,
    SignedEpochRoot, SqliteRevocationOracle,
};
use serde::{Deserialize, Serialize};

use crate::passport_revocation::passport_revocation_oracle_path;

pub const PASSPORT_REVOCATION_LEAVES_SCHEMA: &str = "chio.passport-revocation-leaves.v1";

/// Most leaves in one page.
pub const MAX_PASSPORT_REVOCATION_PAGE_LEAVES: usize = 256;

/// Largest serialized page, in bytes. The publisher fills a page below it and
/// a reader refuses a body above it.
pub const MAX_PASSPORT_REVOCATION_PAGE_BYTES: usize = 512 * 1024;

/// Room kept below [`MAX_PASSPORT_REVOCATION_PAGE_BYTES`] for the page
/// envelope around its leaves.
const PAGE_ENVELOPE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PassportRevocationFeedError {
    #[error("passport revocation oracle unavailable: {0}")]
    OracleUnavailable(String),
    #[error("authority clock reads {now_unix_ms}, before the revocation oracle root at {root_issued_at_unix_ms}")]
    ClockBehindOracle {
        now_unix_ms: u64,
        root_issued_at_unix_ms: u64,
    },
    #[error("passport revocation root signing failed: {0}")]
    Signing(String),
    #[error("passport revocation leaf cursor {0} is out of range")]
    CursorOutOfRange(u64),
    #[error("passport revocation leaf {0} cannot be published: {1}")]
    UnpublishableLeaf(u64, String),
}

/// One revocation leaf in the oracle's insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportRevocationLeaf {
    pub seq: u64,
    pub subject: String,
    pub epoch_nonce: u64,
}

/// The leaves with a sequence number above `after`, in sequence order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportRevocationLeavesPage {
    pub schema: String,
    pub after: u64,
    pub leaves: Vec<PassportRevocationLeaf>,
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

/// Opens the oracle beside `registry` when it exists. An absent oracle holds
/// no revocation, because every revocation writes the oracle first.
fn existing_oracle(
    registry: &Path,
) -> Result<Option<SqliteRevocationOracle>, PassportRevocationFeedError> {
    let unavailable = |error: String| PassportRevocationFeedError::OracleUnavailable(error);
    let path = passport_revocation_oracle_path(registry)
        .map_err(|error| unavailable(error.to_string()))?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(unavailable(error.to_string())),
        Ok(_) => SqliteRevocationOracle::open(&path)
            .map(Some)
            .map_err(|error| unavailable(error.to_string())),
    }
}

/// Signs the current root of the oracle beside `registry` at `now_unix_ms`.
pub fn sign_passport_revocation_root(
    registry: &Path,
    authority: Keypair,
    now_unix_ms: u64,
) -> Result<SignedEpochRoot, PassportRevocationFeedError> {
    let root = match existing_oracle(registry)? {
        Some(oracle) => oracle
            .current_epoch_root()
            .map_err(|error| PassportRevocationFeedError::OracleUnavailable(error.to_string()))?,
        None => InMemoryRevocationOracle::new().epoch_root(),
    };
    if now_unix_ms < root.issued_at_unix_ms {
        return Err(PassportRevocationFeedError::ClockBehindOracle {
            now_unix_ms,
            root_issued_at_unix_ms: root.issued_at_unix_ms,
        });
    }
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

/// The page of leaves after `after` from the oracle beside `registry`, filled
/// up to [`MAX_PASSPORT_REVOCATION_PAGE_LEAVES`] leaves and below
/// [`MAX_PASSPORT_REVOCATION_PAGE_BYTES`].
pub fn passport_revocation_leaves_page(
    registry: &Path,
    after: u64,
) -> Result<PassportRevocationLeavesPage, PassportRevocationFeedError> {
    let cursor =
        i64::try_from(after).map_err(|_| PassportRevocationFeedError::CursorOutOfRange(after))?;
    let stored = match existing_oracle(registry)? {
        Some(oracle) => oracle
            .leaves_after(cursor, MAX_PASSPORT_REVOCATION_PAGE_LEAVES)
            .map_err(|error| PassportRevocationFeedError::OracleUnavailable(error.to_string()))?,
        None => Vec::new(),
    };
    let budget = MAX_PASSPORT_REVOCATION_PAGE_BYTES - PAGE_ENVELOPE_BYTES;
    let mut used = 0_usize;
    let mut leaves = Vec::with_capacity(stored.len());
    for leaf in stored {
        let seq = u64::try_from(leaf.seq).map_err(|_| {
            PassportRevocationFeedError::UnpublishableLeaf(0, "negative sequence".to_owned())
        })?;
        let published = PassportRevocationLeaf {
            seq,
            subject: leaf.key.subject_id.as_str().to_owned(),
            epoch_nonce: leaf.key.epoch_nonce.get(),
        };
        let bytes = serde_json::to_vec(&published)
            .map_err(|error| {
                PassportRevocationFeedError::UnpublishableLeaf(seq, error.to_string())
            })?
            .len()
            .saturating_add(1);
        if used.saturating_add(bytes) > budget {
            if leaves.is_empty() {
                return Err(PassportRevocationFeedError::UnpublishableLeaf(
                    seq,
                    format!("leaf exceeds the {MAX_PASSPORT_REVOCATION_PAGE_BYTES}-byte page"),
                ));
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
