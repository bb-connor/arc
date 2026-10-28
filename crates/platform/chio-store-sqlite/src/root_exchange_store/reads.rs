//! Retention by digest and the reads the exchange, admission and export use.

use chio_core::root_authority::{
    DelegationContext, EnterpriseProviderIdentity, IdpKeySnapshot, RootPolicy, Sha256Digest,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use super::projection::{read_root_row_by_context, required_root};
use super::{
    canonical_blob, decode_blob, digest_column, parse_digest_column, sql_u64, sqlite_error,
    BearerLookup, ContextOpenings, OpeningState, Result, RetainedArtifact, RootExchangeStoreError,
    SqliteRootExchangeStore, StoredRoot,
};

pub(super) const POLICY_BOUND: usize = 1_048_576;
pub(super) const RETAINED_BOUND: usize = 262_144;

#[derive(Clone, Copy)]
pub(super) enum Retained {
    Policy,
    Identity,
    Snapshot,
}

impl Retained {
    pub(super) const fn artifact(self) -> RetainedArtifact {
        match self {
            Self::Policy => RetainedArtifact::RootPolicy,
            Self::Identity => RetainedArtifact::ProviderIdentity,
            Self::Snapshot => RetainedArtifact::KeySnapshot,
        }
    }

    const fn select(self) -> &'static str {
        match self {
            Self::Policy => {
                "SELECT policy FROM root_exchange_policies WHERE root_policy_digest = ?1"
            }
            Self::Identity => {
                "SELECT identity FROM root_exchange_provider_identities WHERE provider_identity_digest = ?1"
            }
            Self::Snapshot => {
                "SELECT snapshot FROM root_exchange_key_snapshots WHERE snapshot_digest = ?1"
            }
        }
    }

    const fn bound(self) -> usize {
        match self {
            Self::Policy => POLICY_BOUND,
            Self::Identity | Self::Snapshot => RETAINED_BOUND,
        }
    }
}

fn retained_bytes(
    connection: &Connection,
    retained: Retained,
    digest: &Sha256Digest,
) -> Result<Option<Vec<u8>>> {
    connection
        .query_row(retained.select(), [digest_column(digest)], |row| row.get(0))
        .optional()
        .map_err(sqlite_error)
}

/// Insert-if-absent by recomputed digest. Identical bytes are a no-op;
/// different bytes under the same digest refuse.
fn retain(
    tx: &Transaction<'_>,
    retained: Retained,
    digest: &Sha256Digest,
    bytes: &[u8],
    insert: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match retained_bytes(tx, retained, digest)? {
        Some(existing) if existing == bytes => Ok(()),
        Some(_) => Err(RootExchangeStoreError::RetainedDigestMismatch {
            kind: retained.artifact(),
        }),
        None => insert(),
    }
}

fn digest_of<T>(
    retained: Retained,
    digest: impl FnOnce(&T) -> chio_core::Result<Sha256Digest>,
    value: &T,
) -> Result<Sha256Digest> {
    digest(value).map_err(|_| RootExchangeStoreError::RetainedDigestMismatch {
        kind: retained.artifact(),
    })
}

pub(super) fn retain_policy(tx: &Transaction<'_>, policy: &RootPolicy) -> Result<()> {
    let digest = digest_of(Retained::Policy, RootPolicy::digest, policy)?;
    let bytes = canonical_blob(policy)?;
    retain(tx, Retained::Policy, &digest, &bytes, || {
        tx.execute(
            "INSERT INTO root_exchange_policies (root_policy_digest, policy) VALUES (?1, ?2)",
            params![digest_column(&digest), bytes],
        )
        .map(|_| ())
        .map_err(sqlite_error)
    })
}

pub(super) fn retain_identity(
    tx: &Transaction<'_>,
    identity: &EnterpriseProviderIdentity,
) -> Result<()> {
    let digest = digest_of(
        Retained::Identity,
        EnterpriseProviderIdentity::digest,
        identity,
    )?;
    let bytes = canonical_blob(identity)?;
    retain(tx, Retained::Identity, &digest, &bytes, || {
        tx.execute(
            "INSERT INTO root_exchange_provider_identities (provider_identity_digest, identity)
             VALUES (?1, ?2)",
            params![digest_column(&digest), bytes],
        )
        .map(|_| ())
        .map_err(sqlite_error)
    })
}

/// Returns whether the snapshot was newly recorded.
pub(super) fn retain_snapshot(tx: &Transaction<'_>, snapshot: &IdpKeySnapshot) -> Result<bool> {
    let digest = digest_of(Retained::Snapshot, IdpKeySnapshot::digest, snapshot)?;
    let bytes = canonical_blob(snapshot)?;
    let mut inserted = false;
    retain(tx, Retained::Snapshot, &digest, &bytes, || {
        inserted = true;
        tx.execute(
            "INSERT INTO root_exchange_key_snapshots (snapshot_digest, issuer, observed_at, snapshot)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                digest_column(&digest),
                snapshot.issuer.as_str(),
                sql_u64(snapshot.observed_at)?,
                bytes
            ],
        )
        .map(|_| ())
        .map_err(sqlite_error)
    })?;
    Ok(inserted)
}

/// Read retained bytes by digest and re-verify the digest of what is read.
fn read_retained<T: serde::de::DeserializeOwned + serde::Serialize>(
    connection: &Connection,
    retained: Retained,
    digest: &Sha256Digest,
    recompute: impl FnOnce(&T) -> chio_core::Result<Sha256Digest>,
) -> Result<T> {
    let bytes = retained_bytes(connection, retained, digest)?.ok_or_else(|| {
        RootExchangeStoreError::RetainedArtifactMissing {
            kind: retained.artifact(),
            digest: *digest,
        }
    })?;
    let mismatch = || RootExchangeStoreError::RetainedDigestMismatch {
        kind: retained.artifact(),
    };
    let value: T = decode_blob(&bytes, retained.bound()).map_err(|_| mismatch())?;
    if recompute(&value).map_err(|_| mismatch())? != *digest {
        return Err(mismatch());
    }
    Ok(value)
}

pub(super) fn verify_retained_table(connection: &Connection, retained: Retained) -> Result<()> {
    let sql = match retained {
        Retained::Policy => "SELECT root_policy_digest FROM root_exchange_policies",
        Retained::Identity => {
            "SELECT provider_identity_digest FROM root_exchange_provider_identities"
        }
        Retained::Snapshot => "SELECT snapshot_digest FROM root_exchange_key_snapshots",
    };
    let mut statement = connection.prepare(sql).map_err(sqlite_error)?;
    let digests = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    for digest in digests {
        let digest = parse_digest_column(&digest)?;
        match retained {
            Retained::Policy => {
                read_retained::<RootPolicy>(connection, retained, &digest, RootPolicy::digest)
                    .map(|_| ())?
            }
            Retained::Identity => read_retained::<EnterpriseProviderIdentity>(
                connection,
                retained,
                &digest,
                EnterpriseProviderIdentity::digest,
            )
            .map(|_| ())?,
            Retained::Snapshot => read_retained::<IdpKeySnapshot>(
                connection,
                retained,
                &digest,
                IdpKeySnapshot::digest,
            )
            .map(|_| ())?,
        }
    }
    Ok(())
}

impl SqliteRootExchangeStore {
    /// The checked stored root, or `AnchoredRootMissing`.
    pub fn presentation(&self, capability_id: &str) -> Result<StoredRoot> {
        self.read_only(|tx| required_root(tx, capability_id))
    }

    pub fn delegation_context(&self, digest: &Sha256Digest) -> Result<DelegationContext> {
        self.read_only(|tx| {
            let row = read_root_row_by_context(tx, digest)?
                .ok_or(RootExchangeStoreError::DelegationContextMissing { digest: *digest })?;
            Ok(row.verify()?.context)
        })
    }

    pub fn root_policy(&self, digest: &Sha256Digest) -> Result<RootPolicy> {
        self.read_only(|tx| read_retained(tx, Retained::Policy, digest, RootPolicy::digest))
    }

    pub fn provider_identity(&self, digest: &Sha256Digest) -> Result<EnterpriseProviderIdentity> {
        self.read_only(|tx| {
            read_retained(
                tx,
                Retained::Identity,
                digest,
                EnterpriseProviderIdentity::digest,
            )
        })
    }

    pub fn idp_key_snapshot(&self, digest: &Sha256Digest) -> Result<IdpKeySnapshot> {
        self.read_only(|tx| read_retained(tx, Retained::Snapshot, digest, IdpKeySnapshot::digest))
    }

    /// Disclosure-scoped: the salts of one root's delegation context.
    /// `Unknown` when no root and no tombstone carries that context.
    pub fn context_openings(&self, context_digest: &Sha256Digest) -> Result<ContextOpenings> {
        self.read_only(|tx| {
            let Some(row) = read_root_row_by_context(tx, context_digest)? else {
                return Ok(ContextOpenings::Unknown);
            };
            row.verify()?;
            let mut statement = tx
                .prepare(
                    "SELECT salt_ref, state, salt FROM root_exchange_openings
                     WHERE capability_id = ?1 ORDER BY salt_ref",
                )
                .map_err(sqlite_error)?;
            let entries = statement
                .query_map([&row.capability_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                })
                .map_err(sqlite_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            let mut openings = Vec::with_capacity(entries.len());
            for (salt_ref, state, salt) in entries {
                let state = match (state.as_str(), salt) {
                    ("present", Some(salt)) => OpeningState::Present(
                        salt.try_into()
                            .map_err(|_| super::invalid("stored salt is not 32 bytes"))?,
                    ),
                    ("erased", None) => OpeningState::Erased,
                    _ => return Err(super::invalid("stored opening state is malformed")),
                };
                openings.push((salt_ref, state));
            }
            Ok(ContextOpenings::Known(openings))
        })
    }

    /// The root a bearer token maps to. An expired root is reported, never
    /// returned.
    pub fn bearer_root(
        &self,
        token_digest: &Sha256Digest,
        trusted_now_unix_ms: u64,
    ) -> Result<BearerLookup> {
        let now = trusted_now_unix_ms / 1000;
        self.read_only(|tx| {
            let mapped: Option<String> = tx
                .query_row(
                    "SELECT capability_id FROM root_exchange_bearer_tokens WHERE token_digest = ?1",
                    [digest_column(token_digest)],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            let Some(capability_id) = mapped else {
                return Ok(BearerLookup::Unknown);
            };
            let stored = required_root(tx, &capability_id)?;
            if stored.capability.expires_at <= now {
                return Ok(BearerLookup::Expired { capability_id });
            }
            Ok(BearerLookup::Live(Box::new(stored)))
        })
    }

    /// Every tag generation a stored root references must be loaded.
    pub(super) fn verify_tag_generations(&self, loaded: &[Sha256Digest]) -> Result<()> {
        self.read_only(|tx| {
            let mut statement = tx
                .prepare("SELECT DISTINCT tag_key_id FROM root_exchange_roots ORDER BY tag_key_id")
                .map_err(sqlite_error)?;
            let referenced = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(sqlite_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            for key_id in referenced {
                let key_id = parse_digest_column(&key_id)?;
                if !loaded.contains(&key_id) {
                    return Err(RootExchangeStoreError::TagGenerationMissing { key_id });
                }
            }
            Ok(())
        })
    }
}
