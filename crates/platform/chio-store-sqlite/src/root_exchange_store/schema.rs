//! One v1 schema for the root exchange, its global commit projection and the
//! invariants checked whenever the serving store opens.

use rusqlite::{params, Connection, OptionalExtension};

use super::projection::all_root_rows;
use super::reads::{verify_retained_table, Retained};
use super::{digest_column, owner_invalid, RootExchangeIntegrityError, RootExchangeStoreError};
use crate::serving_owner::SqliteServingOwnerError;

const SCHEMA_KEY: &str = "root_exchange";
const SCHEMA: &str = include_str!("../root_exchange_store.sql");

pub(crate) const PROJECTION: &str = "root_exchange";
pub(super) const PROJECTION_KEY: &str = "root_exchange";

pub(crate) fn initialize_root_exchange_schema(
    schema: &crate::schema_version::SchemaTransaction<'_>,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let transaction = schema.connection();
    if schema.is_fresh() {
        transaction.execute_batch(SCHEMA)?;
        schema
            .stamp(SCHEMA_KEY)
            .map_err(|error| owner_invalid(error.to_string()))?;
    }
    verify_root_exchange_invariants(transaction)
}

/// Every root row passes its row check and has its mint event; every present opening has its root
/// and no recorded erasure; every retained artifact matches its digest; every live replay binding
/// and bearer mapping agrees with its recorded history.
pub(crate) fn verify_root_exchange_invariants(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    verify_integrity(connection).map_err(SqliteServingOwnerError::RootExchange)
}

fn verify_integrity(
    connection: &Connection,
) -> std::result::Result<(), RootExchangeIntegrityError> {
    let unreadable =
        |error: &dyn std::fmt::Display| RootExchangeIntegrityError::Unreadable(error.to_string());
    for row in all_root_rows(connection).map_err(|error| unreadable(&error))? {
        let event: Option<String> = connection
            .query_row(
                "SELECT digest FROM root_exchange_events
                 WHERE mutation = 'mint' AND subject = ?1",
                [&row.capability_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| unreadable(&error))?;
        let Some(event) = event else {
            return Err(RootExchangeIntegrityError::RootWithoutGlobalCommit {
                capability_id: row.capability_id,
            });
        };
        let tampered = || RootExchangeIntegrityError::RootTampered {
            capability_id: row.capability_id.clone(),
        };
        match row.verify() {
            Ok(_) => {}
            Err(RootExchangeStoreError::AnchoredRootTampered { .. }) => return Err(tampered()),
            Err(error) => return Err(unreadable(&error)),
        }
        if event != digest_column(&row.authorization_projection_digest) {
            return Err(tampered());
        }
    }
    let orphan: Option<String> = connection
        .query_row(
            "SELECT o.capability_id FROM root_exchange_openings o
             WHERE o.state = 'present' AND NOT EXISTS (
                 SELECT 1 FROM root_exchange_roots r WHERE r.capability_id = o.capability_id)
             ORDER BY o.capability_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| unreadable(&error))?;
    if let Some(capability_id) = orphan {
        return Err(RootExchangeIntegrityError::OpeningWithoutRoot { capability_id });
    }
    let restored: Option<String> = connection
        .query_row(
            "SELECT o.capability_id FROM root_exchange_openings o
             WHERE o.state = 'present' AND EXISTS (
                 SELECT 1 FROM root_exchange_events e
                 WHERE e.mutation = 'erase_openings' AND e.subject = o.capability_id)
             ORDER BY o.capability_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| unreadable(&error))?;
    if let Some(capability_id) = restored {
        return Err(RootExchangeIntegrityError::ErasedOpeningPresent { capability_id });
    }
    for retained in [Retained::Policy, Retained::Identity, Retained::Snapshot] {
        match verify_retained_table(connection, retained) {
            Ok(()) => {}
            Err(RootExchangeStoreError::RetainedDigestMismatch { kind }) => {
                return Err(RootExchangeIntegrityError::RetainedDigestMismatch { kind })
            }
            Err(error) => return Err(unreadable(&error)),
        }
    }
    super::bindings::verify_live_state(connection)
}

/// The digest the global commit chain references for one root exchange event.
pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> std::result::Result<String, SqliteServingOwnerError> {
    if key != PROJECTION_KEY {
        return Err(owner_invalid("root exchange projection key is invalid"));
    }
    let sequence = i64::try_from(sequence)
        .map_err(|_| owner_invalid("root exchange projection sequence is out of range"))?;
    let row: Option<(String, String, String, i64)> = connection
        .query_row(
            "SELECT mutation, subject, digest, occurred_at FROM root_exchange_events
             WHERE sequence = ?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (mutation, subject, digest, occurred_at) =
        row.ok_or_else(|| owner_invalid("root exchange projection reference is absent"))?;
    let (replay, bearer) = super::bindings::recorded(connection, sequence)?;
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.root-exchange-event.v1",
        sequence,
        mutation,
        subject,
        digest,
        occurred_at,
        replay,
        bearer,
    ))
    .map_err(|error| owner_invalid(error.to_string()))?;
    Ok(chio_core::sha256_hex(&bytes))
}

/// Every root exchange event has exactly one global reference, and every
/// global reference names an event.
pub(crate) fn verify_projection_coverage(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let events: i64 =
        connection.query_row("SELECT COUNT(*) FROM root_exchange_events", [], |row| {
            row.get(0)
        })?;
    let global: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
        [PROJECTION],
        |row| row.get(0),
    )?;
    let matched: i64 = connection.query_row(
        "SELECT COUNT(*) FROM root_exchange_events e
         JOIN authority_global_commits g
           ON g.projection_kind = ?1 AND g.projection_key = ?2
          AND g.projection_sequence = e.sequence",
        params![PROJECTION, PROJECTION_KEY],
        |row| row.get(0),
    )?;
    if events != global || events != matched {
        return Err(owner_invalid(
            "root exchange events and global commits do not correspond",
        ));
    }
    Ok(())
}
