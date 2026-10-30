//! Replay bindings and bearer mappings recorded with their events, and the
//! reconciliation of the live tables against that recorded history.
//!
//! A live row may be absent only after its retention ended: legitimate
//! removal (pruning, or an expired row deleted before a rebind) happens only
//! inside a mutation whose event records the trusted time it ran at, and
//! only for rows whose retention ended by then. At open, the latest event
//! time bounds every legitimate removal; at admission, the admission's own
//! trusted time does.

use chio_core::root_authority::Sha256Digest;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use super::{
    digest_column, parse_digest_column, sql_u64, sqlite_error, stored_u64, Result,
    RootExchangeIntegrityError, RootExchangeStoreError,
};

/// One replay binding as its event records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ReplayRecord {
    pub(super) replay_key_digest: String,
    pub(super) namespace: String,
    pub(super) bound_at: u64,
    pub(super) retain_until: u64,
    pub(super) capability_id: Option<String>,
}

/// One bearer mapping as its event records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct BearerRecord {
    pub(super) token_digest: String,
    pub(super) capability_id: String,
    pub(super) retain_until: u64,
}

pub(super) fn insert_records(
    connection: &Connection,
    sequence: u64,
    replay: Option<&ReplayRecord>,
    bearer: Option<&BearerRecord>,
) -> Result<()> {
    let sequence = sql_u64(sequence)?;
    if let Some(replay) = replay {
        connection
            .execute(
                "INSERT INTO root_exchange_replay_bindings
                     (sequence, replay_key_digest, namespace, bound_at, retain_until, capability_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    sequence,
                    replay.replay_key_digest,
                    replay.namespace,
                    sql_u64(replay.bound_at)?,
                    sql_u64(replay.retain_until)?,
                    replay.capability_id,
                ],
            )
            .map_err(sqlite_error)?;
    }
    if let Some(bearer) = bearer {
        connection
            .execute(
                "INSERT INTO root_exchange_bearer_bindings
                     (sequence, token_digest, capability_id, retain_until)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    sequence,
                    bearer.token_digest,
                    bearer.capability_id,
                    sql_u64(bearer.retain_until)?,
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

/// The records an event's global reference covers.
pub(super) fn recorded(
    connection: &Connection,
    sequence: i64,
) -> rusqlite::Result<(Option<ReplayRecord>, Option<BearerRecord>)> {
    let replay = connection
        .query_row(
            "SELECT replay_key_digest, namespace, bound_at, retain_until, capability_id
             FROM root_exchange_replay_bindings WHERE sequence = ?1",
            [sequence],
            raw_replay,
        )
        .optional()?;
    let bearer = connection
        .query_row(
            "SELECT token_digest, capability_id, retain_until
             FROM root_exchange_bearer_bindings WHERE sequence = ?1",
            [sequence],
            raw_bearer,
        )
        .optional()?;
    Ok((replay, bearer))
}

fn stored_integer(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn raw_replay(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReplayRecord> {
    Ok(ReplayRecord {
        replay_key_digest: row.get(0)?,
        namespace: row.get(1)?,
        bound_at: stored_integer(row, 2)?,
        retain_until: stored_integer(row, 3)?,
        capability_id: row.get(4)?,
    })
}

fn raw_bearer(row: &rusqlite::Row<'_>) -> rusqlite::Result<BearerRecord> {
    Ok(BearerRecord {
        token_digest: row.get(0)?,
        capability_id: row.get(1)?,
        retain_until: stored_integer(row, 2)?,
    })
}

fn latest_replay_record(
    connection: &Connection,
    replay_key_digest: &str,
) -> rusqlite::Result<Option<ReplayRecord>> {
    connection
        .query_row(
            "SELECT replay_key_digest, namespace, bound_at, retain_until, capability_id
             FROM root_exchange_replay_bindings WHERE replay_key_digest = ?1
             ORDER BY sequence DESC LIMIT 1",
            [replay_key_digest],
            raw_replay,
        )
        .optional()
}

fn live_replay_row(
    connection: &Connection,
    replay_key_digest: &str,
) -> rusqlite::Result<Option<ReplayRecord>> {
    connection
        .query_row(
            "SELECT replay_key_digest, namespace, bound_at, retain_until, capability_id
             FROM root_exchange_replay WHERE replay_key_digest = ?1",
            [replay_key_digest],
            raw_replay,
        )
        .optional()
}

fn latest_bearer_record(
    connection: &Connection,
    token_digest: &str,
) -> rusqlite::Result<Option<BearerRecord>> {
    connection
        .query_row(
            "SELECT token_digest, capability_id, retain_until
             FROM root_exchange_bearer_bindings WHERE token_digest = ?1
             ORDER BY sequence DESC LIMIT 1",
            [token_digest],
            raw_bearer,
        )
        .optional()
}

fn live_bearer_row(
    connection: &Connection,
    token_digest: &str,
) -> rusqlite::Result<Option<BearerRecord>> {
    connection
        .query_row(
            "SELECT token_digest, capability_id, retain_until
             FROM root_exchange_bearer_tokens WHERE token_digest = ?1",
            [token_digest],
            raw_bearer,
        )
        .optional()
}

fn root_expires_at(connection: &Connection, capability_id: &str) -> rusqlite::Result<Option<u64>> {
    connection
        .query_row(
            "SELECT expires_at FROM root_exchange_roots WHERE capability_id = ?1",
            [capability_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| {
            u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
        })
        .transpose()
}

/// Why a live row disagrees with its recorded history.
enum Divergence {
    Missing,
    Mismatch,
}

/// The live replay row of one key against its latest recorded binding, at
/// a time no legitimate removal ran after.
fn replay_divergence(
    connection: &Connection,
    replay_key_digest: &str,
    removal_horizon: u64,
) -> rusqlite::Result<Option<Divergence>> {
    let row = live_replay_row(connection, replay_key_digest)?;
    let record = latest_replay_record(connection, replay_key_digest)?;
    Ok(match (row, record) {
        (Some(row), Some(record)) if row == record => None,
        (Some(_), _) => Some(Divergence::Mismatch),
        (None, Some(record)) if record.retain_until > removal_horizon => Some(Divergence::Missing),
        (None, _) => None,
    })
}

/// The live bearer mapping of one token against its latest recorded
/// mapping. A mapping is removed when its retention ends or its root
/// expires.
fn bearer_divergence(
    connection: &Connection,
    token_digest: &str,
    removal_horizon: u64,
) -> rusqlite::Result<Option<Divergence>> {
    let row = live_bearer_row(connection, token_digest)?;
    let record = latest_bearer_record(connection, token_digest)?;
    Ok(match (row, record) {
        (Some(row), Some(record)) if row == record => None,
        (Some(_), _) => Some(Divergence::Mismatch),
        (None, Some(record)) => {
            let root_expired = root_expires_at(connection, &record.capability_id)?
                .is_some_and(|expires_at| expires_at <= removal_horizon);
            (record.retain_until > removal_horizon && !root_expired).then_some(Divergence::Missing)
        }
        (None, None) => None,
    })
}

/// Admission of one replay key at trusted time `now`.
pub(super) fn admit_replay_key(
    connection: &Connection,
    replay_key_digest: &Sha256Digest,
    now: u64,
) -> Result<()> {
    match replay_divergence(connection, &digest_column(replay_key_digest), now)
        .map_err(sqlite_error)?
    {
        None => Ok(()),
        Some(Divergence::Missing) => Err(RootExchangeStoreError::ReplayBindingMissing {
            replay_key_digest: *replay_key_digest,
        }),
        Some(Divergence::Mismatch) => Err(RootExchangeStoreError::ReplayBindingMismatch {
            replay_key_digest: *replay_key_digest,
        }),
    }
}

/// Admission of one bearer token at trusted time `now`.
pub(super) fn admit_bearer_token(
    connection: &Connection,
    token_digest: &Sha256Digest,
    now: u64,
) -> Result<()> {
    match bearer_divergence(connection, &digest_column(token_digest), now).map_err(sqlite_error)? {
        None => Ok(()),
        Some(Divergence::Missing) => Err(RootExchangeStoreError::BearerMappingMissing {
            token_digest: *token_digest,
        }),
        Some(Divergence::Mismatch) => Err(RootExchangeStoreError::BearerMappingMismatch {
            token_digest: *token_digest,
        }),
    }
}

fn distinct(connection: &Connection, sql: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(sql)?;
    let values = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(values)
}

/// Every live replay row and bearer mapping agrees with its latest recorded
/// binding, every recorded binding still within retention at the latest
/// event time has its live row, and every rebind of a replay key followed
/// the end of the previous binding's retention.
pub(super) fn verify_live_state(
    connection: &Connection,
) -> std::result::Result<(), RootExchangeIntegrityError> {
    let unreadable =
        |error: rusqlite::Error| RootExchangeIntegrityError::Unreadable(error.to_string());
    let digest = |value: &str| {
        parse_digest_column(value)
            .map_err(|error| RootExchangeIntegrityError::Unreadable(error.to_string()))
    };
    let horizon: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(occurred_at), 0) FROM root_exchange_events",
            [],
            |row| row.get(0),
        )
        .map_err(unreadable)?;
    let horizon = stored_u64(horizon)
        .map_err(|error| RootExchangeIntegrityError::Unreadable(error.to_string()))?;
    let unrecorded: Option<i64> = connection
        .query_row(
            "SELECT b.sequence FROM root_exchange_replay_bindings b
             LEFT JOIN root_exchange_events e ON e.sequence = b.sequence
             WHERE e.mutation IS NULL OR e.mutation NOT IN ('mint', 'client_assertion')
             UNION ALL
             SELECT b.sequence FROM root_exchange_bearer_bindings b
             LEFT JOIN root_exchange_events e ON e.sequence = b.sequence
             WHERE e.mutation IS NULL OR e.mutation <> 'mint'
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(unreadable)?;
    if let Some(sequence) = unrecorded {
        return Err(RootExchangeIntegrityError::Unreadable(format!(
            "recorded binding {sequence} has no binding event"
        )));
    }
    for key in distinct(
        connection,
        "SELECT replay_key_digest FROM root_exchange_replay
         UNION SELECT replay_key_digest FROM root_exchange_replay_bindings
         ORDER BY 1",
    )
    .map_err(unreadable)?
    {
        match replay_divergence(connection, &key, horizon).map_err(unreadable)? {
            None => {}
            Some(Divergence::Missing) => {
                return Err(RootExchangeIntegrityError::ReplayBindingMissing {
                    replay_key_digest: digest(&key)?,
                })
            }
            Some(Divergence::Mismatch) => {
                return Err(RootExchangeIntegrityError::ReplayBindingMismatch {
                    replay_key_digest: digest(&key)?,
                })
            }
        }
    }
    let early_rebind: Option<String> = connection
        .query_row(
            "SELECT later.replay_key_digest
             FROM root_exchange_replay_bindings later
             JOIN root_exchange_replay_bindings earlier
               ON earlier.replay_key_digest = later.replay_key_digest
              AND earlier.sequence = (
                  SELECT MAX(sequence) FROM root_exchange_replay_bindings
                  WHERE replay_key_digest = later.replay_key_digest
                    AND sequence < later.sequence)
             WHERE earlier.retain_until > later.bound_at
             ORDER BY later.sequence LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(unreadable)?;
    if let Some(key) = early_rebind {
        return Err(RootExchangeIntegrityError::ReplayBindingMismatch {
            replay_key_digest: digest(&key)?,
        });
    }
    for token in distinct(
        connection,
        "SELECT token_digest FROM root_exchange_bearer_tokens
         UNION SELECT token_digest FROM root_exchange_bearer_bindings
         ORDER BY 1",
    )
    .map_err(unreadable)?
    {
        match bearer_divergence(connection, &token, horizon).map_err(unreadable)? {
            None => {}
            Some(Divergence::Missing) => {
                return Err(RootExchangeIntegrityError::BearerMappingMissing {
                    token_digest: digest(&token)?,
                })
            }
            Some(Divergence::Mismatch) => {
                return Err(RootExchangeIntegrityError::BearerMappingMismatch {
                    token_digest: digest(&token)?,
                })
            }
        }
    }
    Ok(())
}
