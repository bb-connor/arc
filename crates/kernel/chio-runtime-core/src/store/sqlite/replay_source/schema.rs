use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use rusqlite::Connection;

use super::{invalid, sqlite_error, ChioRuntimeError};

// Match the original marker definitions, including their stored SQL. Sealing
// accepts this legacy schema only; it does not repair or reinterpret variants.
const MARKER_SCHEMA: &str = r#"
CREATE TABLE runtime_consumed_leases (
                    lease_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
CREATE TABLE runtime_consumed_treaty_continuations (
                    continuation_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
CREATE TABLE runtime_consumed_swarm_continuations (
                    continuation_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
"#;

pub(super) const SEAL_TABLE_SCHEMA: &str = r#"
CREATE TABLE runtime_replay_source_seal (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    canonical_bytes BLOB NOT NULL CHECK (
        typeof(canonical_bytes) = 'blob'
        AND length(canonical_bytes) > 0
        AND length(canonical_bytes) <= 8388608
    )
);
"#;

const CATALOG_FILTER: &str = "lower(name) GLOB '*runtime_replay_source*' OR lower(tbl_name) IN (
    'runtime_consumed_leases', 'runtime_consumed_treaty_continuations',
    'runtime_consumed_swarm_continuations', 'runtime_replay_source_seal'
)";

type CatalogEntry = (String, String, String, Option<String>);

pub(super) fn has_seal_evidence(connection: &Connection) -> Result<bool, ChioRuntimeError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE lower(name) GLOB '*runtime_replay_source*'
                OR lower(tbl_name) = 'runtime_replay_source_seal')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

pub(super) fn barrier_sql() -> String {
    let mut sql = String::new();
    for (name, table) in [
        ("lease", "runtime_consumed_leases"),
        ("treaty", "runtime_consumed_treaty_continuations"),
        ("swarm", "runtime_consumed_swarm_continuations"),
        ("seal", "runtime_replay_source_seal"),
    ] {
        for (suffix, operation) in [
            ("no_insert", "INSERT"),
            ("no_update", "UPDATE"),
            ("no_delete", "DELETE"),
        ] {
            sql.push_str(&format!(
                "CREATE TRIGGER runtime_replay_source_{name}_{suffix}\n\
                 BEFORE {operation} ON {table}\n\
                 BEGIN\n\
                     SELECT RAISE(ABORT, 'runtime replay source is sealed');\n\
                 END;\n"
            ));
        }
    }
    sql
}

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, ChioRuntimeError> {
    // Bound untrusted schema text before allocating its strings. This also
    // rejects unexpected indexes/triggers on any protected table.
    let (count, bytes): (i64, i64) = connection
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(
                    length(CAST(type AS BLOB)) + length(CAST(name AS BLOB))
                    + length(CAST(tbl_name AS BLOB))
                    + COALESCE(length(CAST(sql AS BLOB)), 0)), 0)
                 FROM sqlite_schema WHERE {CATALOG_FILTER}"
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if !(0..=64).contains(&count) || !(0..=65_536).contains(&bytes) {
        return Err(invalid("replay source schema exceeds its bounds"));
    }
    let mut statement = connection
        .prepare(&format!(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE {CATALOG_FILTER}
             ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY"
        ))
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

fn expected_catalog(sealed: bool) -> Result<Vec<CatalogEntry>, ChioRuntimeError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(MARKER_SCHEMA)
        .map_err(sqlite_error)?;
    if sealed {
        expected
            .execute_batch(SEAL_TABLE_SCHEMA)
            .map_err(sqlite_error)?;
        expected
            .execute_batch(&barrier_sql())
            .map_err(sqlite_error)?;
    }
    catalog(&expected)
}

pub(super) fn verify_schema(connection: &Connection, sealed: bool) -> Result<(), ChioRuntimeError> {
    if catalog(connection)? != expected_catalog(sealed)? {
        return Err(invalid(
            "replay source schema differs from its canonical definition",
        ));
    }
    Ok(())
}

pub(super) fn barrier_sha256() -> Result<String, ChioRuntimeError> {
    let bytes = canonical_json_bytes(&expected_catalog(true)?)
        .map_err(|error| invalid(format!("replay barrier encoding failed: {error}")))?;
    Ok(sha256_hex(&bytes))
}
