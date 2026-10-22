//! Client-assertion replay, opening erasure, key snapshots and pruning.

use chio_core::root_authority::{IdpKeySnapshot, Sha256Digest};
use chio_core::StoreMutationFence;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use super::projection::read_root_row;
use super::reads::retain_snapshot;
use super::{
    change_digest, digest_column, sql_u64, sqlite_error, stored_u64, Change, MintRequestRefusal,
    Mutation, Result, RetainedArtifact, SqliteRootExchangeStore, SqliteRootExchangeStoreError,
};

#[derive(Serialize)]
struct ClientAssertionBody {
    replay_key_digest: String,
    bound_at: u64,
    retain_until: u64,
}

#[derive(Serialize)]
struct EraseBody<'a> {
    capability_id: &'a str,
    salt_refs: Vec<String>,
}

#[derive(Serialize)]
struct PruneBody {
    now: u64,
    replay_rows: u64,
    bearer_rows: u64,
}

impl SqliteRootExchangeStore {
    /// Bind a client-assertion `jti` digest once, until `retain_until`.
    pub fn bind_client_assertion(
        &self,
        replay_key_digest: &Sha256Digest,
        retain_until: u64,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            if retain_until <= now {
                return Err(SqliteRootExchangeStoreError::InvalidMintRequest(
                    MintRequestRefusal::ReplayRetentionPast,
                ));
            }
            let replay = digest_column(replay_key_digest);
            let retained: Option<i64> = tx
                .query_row(
                    "SELECT retain_until FROM root_exchange_replay WHERE replay_key_digest = ?1",
                    [&replay],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            if let Some(retained) = retained {
                if stored_u64(retained)? > now {
                    return Err(SqliteRootExchangeStoreError::AssertionReplay);
                }
                tx.execute(
                    "DELETE FROM root_exchange_replay WHERE replay_key_digest = ?1",
                    [&replay],
                )
                .map_err(sqlite_error)?;
            }
            tx.execute(
                "INSERT INTO root_exchange_replay
                     (replay_key_digest, namespace, bound_at, retain_until, capability_id)
                 VALUES (?1, 'client_assertion', ?2, ?3, NULL)",
                params![replay, sql_u64(now)?, sql_u64(retain_until)?],
            )
            .map_err(sqlite_error)?;
            let digest = change_digest(
                Mutation::ClientAssertion,
                &ClientAssertionBody {
                    replay_key_digest: replay.clone(),
                    bound_at: now,
                    retain_until,
                },
            )?;
            Ok((
                (),
                Some(Change {
                    mutation: Mutation::ClientAssertion,
                    subject: replay,
                    digest,
                }),
            ))
        })
    }

    /// Tombstone every present opening of one root. The root stays valid.
    pub fn erase_root_openings(
        &self,
        capability_id: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            if read_root_row(tx, capability_id)?.is_none() {
                return Err(SqliteRootExchangeStoreError::AnchoredRootMissing {
                    capability_id: capability_id.to_owned(),
                });
            }
            let mut statement = tx
                .prepare(
                    "SELECT salt_ref FROM root_exchange_openings
                     WHERE capability_id = ?1 AND state = 'present' ORDER BY salt_ref",
                )
                .map_err(sqlite_error)?;
            let salt_refs = statement
                .query_map([capability_id], |row| row.get::<_, String>(0))
                .map_err(sqlite_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            drop(statement);
            if salt_refs.is_empty() {
                return Ok(((), None));
            }
            tx.execute(
                "UPDATE root_exchange_openings SET state = 'erased', salt = NULL, state_at = ?2
                 WHERE capability_id = ?1 AND state = 'present'",
                params![capability_id, sql_u64(now)?],
            )
            .map_err(sqlite_error)?;
            let digest = change_digest(
                Mutation::EraseOpenings,
                &EraseBody {
                    capability_id,
                    salt_refs,
                },
            )?;
            Ok((
                (),
                Some(Change {
                    mutation: Mutation::EraseOpenings,
                    subject: capability_id.to_owned(),
                    digest,
                }),
            ))
        })
    }

    /// Retain one IdP key snapshot by its verified digest, before the key set
    /// it records is installed.
    pub fn record_idp_key_snapshot(
        &self,
        snapshot: &IdpKeySnapshot,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Sha256Digest> {
        self.mutate(fence, trusted_now_unix_ms, |tx, _| {
            let digest = snapshot.digest().map_err(|_| {
                SqliteRootExchangeStoreError::RetainedDigestMismatch {
                    kind: RetainedArtifact::KeySnapshot,
                }
            })?;
            if !retain_snapshot(tx, snapshot)? {
                return Ok((digest, None));
            }
            let change = Change {
                mutation: Mutation::KeySnapshot,
                subject: digest_column(&digest),
                digest: digest_column(&digest),
            };
            Ok((digest, Some(change)))
        })
    }

    /// Delete replay bindings and bearer mappings past their retention.
    /// Roots are never pruned here.
    pub fn prune_expired(
        &self,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            let now_sql = sql_u64(now)?;
            let replay_rows = tx
                .execute(
                    "DELETE FROM root_exchange_replay WHERE retain_until <= ?1",
                    [now_sql],
                )
                .map_err(sqlite_error)?;
            let bearer_rows = tx
                .execute(
                    "DELETE FROM root_exchange_bearer_tokens WHERE retain_until <= ?1",
                    [now_sql],
                )
                .map_err(sqlite_error)?;
            if replay_rows == 0 && bearer_rows == 0 {
                return Ok(((), None));
            }
            let body = PruneBody {
                now,
                replay_rows: u64::try_from(replay_rows).unwrap_or(u64::MAX),
                bearer_rows: u64::try_from(bearer_rows).unwrap_or(u64::MAX),
            };
            let digest = change_digest(Mutation::Prune, &body)?;
            Ok((
                (),
                Some(Change {
                    mutation: Mutation::Prune,
                    subject: now.to_string(),
                    digest,
                }),
            ))
        })
    }
}
