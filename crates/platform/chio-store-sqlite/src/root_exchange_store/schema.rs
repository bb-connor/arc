//! One v1 schema for the root exchange, its global commit projection and the
//! invariants checked whenever the serving store opens.

use rusqlite::{params, Connection, OptionalExtension};

use super::projection::all_root_rows;
use super::reads::{verify_retained_table, Retained};
use super::{digest_column, owner_invalid};
use crate::serving_owner::SqliteServingOwnerError;

const SCHEMA_KEY: &str = "root_exchange";
const SCHEMA: &str = include_str!("../root_exchange_store.sql");

pub(crate) const PROJECTION: &str = "root_exchange";
pub(super) const PROJECTION_KEY: &str = "root_exchange";

type SchemaCatalogEntry = (String, String, String, Option<String>);

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

/// The schema matches its canonical definition; every root row passes its
/// row check and has its mint event; every present opening has its root;
/// every retained artifact matches its digest.
pub(crate) fn verify_root_exchange_invariants(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    if schema_catalog(connection)? != schema_catalog(&expected)? {
        return Err(owner_invalid(
            "root exchange schema differs from the canonical definition",
        ));
    }
    for row in all_root_rows(connection).map_err(|error| owner_invalid(error.to_string()))? {
        let event: Option<String> = connection
            .query_row(
                "SELECT digest FROM root_exchange_events
                 WHERE mutation = 'mint' AND subject = ?1",
                [&row.capability_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(event) = event else {
            return Err(owner_invalid(format!(
                "anchored root {} has no global commit",
                row.capability_id
            )));
        };
        row.verify()
            .map_err(|error| owner_invalid(error.to_string()))?;
        if event != digest_column(&row.authorization_projection_digest) {
            return Err(owner_invalid(format!(
                "anchored root {} differs from its authorization projection",
                row.capability_id
            )));
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
        .optional()?;
    if let Some(capability_id) = orphan {
        return Err(owner_invalid(format!(
            "root opening of {capability_id} has no anchored root"
        )));
    }
    for retained in [Retained::Policy, Retained::Identity, Retained::Snapshot] {
        verify_retained_table(connection, retained)
            .map_err(|error| owner_invalid(error.to_string()))?;
    }
    Ok(())
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
    let row: Option<(String, String, String)> = connection
        .query_row(
            "SELECT mutation, subject, digest FROM root_exchange_events WHERE sequence = ?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (mutation, subject, digest) =
        row.ok_or_else(|| owner_invalid("root exchange projection reference is absent"))?;
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.root-exchange-event.v1",
        sequence,
        mutation,
        subject,
        digest,
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

fn schema_catalog(
    connection: &Connection,
) -> std::result::Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name GLOB 'root_exchange_*' OR tbl_name GLOB 'root_exchange_*'
         ORDER BY type, name, tbl_name",
    )?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(entries)
}
