//! One v1 schema for the serving D1 allocator, its global commit projection
//! and the invariants checked whenever the serving store opens.

use rand_core::{OsRng, RngCore};

use super::*;

const SCHEMA_KEY: &str = "work_delegation";
const SCHEMA: &str = include_str!("../delegation_store.sql");

pub(crate) const PROJECTION: &str = "work_delegation";
pub(super) const PROJECTION_KEY: &str = "allocator";

type SchemaCatalogEntry = (String, String, String, Option<String>);

pub(crate) fn initialize_work_delegation_schema(
    schema: &crate::schema_version::SchemaTransaction<'_>,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let transaction = schema.connection();

    if schema.is_fresh() {
        transaction.execute_batch(SCHEMA)?;
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        transaction.execute(
            "INSERT INTO work_delegation_namespace (singleton, namespace) VALUES (1, ?1)",
            [hex::encode(bytes)],
        )?;
        schema
            .stamp(SCHEMA_KEY)
            .map_err(|error| owner_invalid(error.to_string()))?;
    }
    verify_work_delegation_invariants(transaction)
}

/// The schema matches its canonical definition, the namespace exists, and
/// every slot's current state is the state its latest event committed.
pub(crate) fn verify_work_delegation_invariants(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    if schema_catalog(connection)? != schema_catalog(&expected)? {
        return Err(owner_invalid(
            "delegation schema differs from the canonical definition",
        ));
    }
    namespace(connection).map_err(|error| owner_invalid(error.to_string()))?;
    let mut statement = connection.prepare(
        "SELECT s.slot_id,
                (SELECT e.state_digest FROM work_delegation_events e
                  WHERE e.slot_id = s.slot_id ORDER BY e.sequence DESC LIMIT 1)
         FROM work_delegation_slots s ORDER BY s.slot_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (slot_id, committed) in rows {
        let state = read(connection, &slot_id)
            .map_err(|error| owner_invalid(error.to_string()))?
            .ok_or_else(|| owner_invalid("delegation slot disappeared"))?;
        let current = state_digest(&state).map_err(|error| owner_invalid(error.to_string()))?;
        if committed.as_deref() != Some(current.as_str()) {
            return Err(owner_invalid(
                "delegation slot state differs from its committed event",
            ));
        }
    }
    Ok(())
}

/// The digest the global commit chain references for one delegation event.
pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> std::result::Result<String, SqliteServingOwnerError> {
    if key != PROJECTION_KEY {
        return Err(owner_invalid("delegation projection key is invalid"));
    }
    let sequence = i64::try_from(sequence)
        .map_err(|_| owner_invalid("delegation projection sequence is out of range"))?;
    let row: Option<(String, String, String)> = connection
        .query_row(
            "SELECT command_id, slot_id, state_digest FROM work_delegation_events WHERE sequence = ?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (command_id, slot_id, state_digest) =
        row.ok_or_else(|| owner_invalid("delegation projection reference is absent"))?;
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.work-delegation-event.v1",
        sequence,
        command_id,
        slot_id,
        state_digest,
    ))
    .map_err(|error| owner_invalid(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Every delegation event has exactly one global reference, and every global
/// reference names a delegation event.
pub(crate) fn verify_projection_coverage(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let events: i64 =
        connection.query_row("SELECT COUNT(*) FROM work_delegation_events", [], |row| {
            row.get(0)
        })?;
    let global: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
        [PROJECTION],
        |row| row.get(0),
    )?;
    let matched: i64 = connection.query_row(
        "SELECT COUNT(*) FROM work_delegation_events e
         JOIN authority_global_commits g
           ON g.projection_kind = ?1 AND g.projection_key = ?2
          AND g.projection_sequence = e.sequence",
        params![PROJECTION, PROJECTION_KEY],
        |row| row.get(0),
    )?;
    if events != global || events != matched {
        return Err(owner_invalid(
            "delegation events and global commits do not correspond",
        ));
    }
    Ok(())
}

fn schema_catalog(
    connection: &Connection,
) -> std::result::Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name GLOB 'work_delegation_*' OR tbl_name GLOB 'work_delegation_*'
         ORDER BY type, name, tbl_name",
    )?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(entries)
}
