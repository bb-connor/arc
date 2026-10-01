use chio_core::{canonical::canonical_json_bytes, sha256_hex};
use rusqlite::Connection;

use super::{invalid, Error};

// Match the current legacy store's exact catalog, not merely its column names.
// Historical ALTER-created variants require separate qualification. Sealing
// must refuse them, not rewrite a live replay namespace to make it qualify.
const MARKER_SCHEMA: &str = r#"
CREATE TABLE chio_governed_approval_replay_entries (
                subject_id              TEXT NOT NULL,
                request_id              TEXT NOT NULL,
                intent_hash             TEXT NOT NULL,
                expires_at              INTEGER NOT NULL,
                dispatch_reservation_id TEXT,
                PRIMARY KEY (subject_id, request_id, intent_hash)
            );
CREATE INDEX idx_chio_governed_approval_replay_expiry
                ON chio_governed_approval_replay_entries(expires_at);
CREATE TABLE chio_governed_approval_replay_clock (
                singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
                wall_clock_high_water INTEGER NOT NULL,
                pruned_through        INTEGER NOT NULL DEFAULT -9223372036854775808
            );
CREATE TABLE chio_governed_approval_replay_limits (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capacity  INTEGER NOT NULL CHECK (capacity > 0)
            );
"#;

pub(super) const SEAL_SCHEMA: &str = r#"
CREATE TABLE chio_governed_approval_replay_source_seal (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    canonical_bytes BLOB NOT NULL CHECK (
        typeof(canonical_bytes) = 'blob'
        AND length(canonical_bytes) > 0
        AND length(canonical_bytes) <= 8388608
    )
);
"#;

const CATALOG_FILTER: &str = "lower(name) GLOB '*governed_approval_replay_source*'
    OR lower(tbl_name) IN ('chio_governed_approval_replay_entries',
    'chio_governed_approval_replay_clock', 'chio_governed_approval_replay_limits',
    'chio_governed_approval_replay_source_seal')";
type CatalogEntry = (String, String, String, Option<String>);

pub(super) fn has_evidence(connection: &Connection) -> Result<bool, Error> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema
         WHERE lower(name) GLOB '*governed_approval_replay_source*'
            OR lower(tbl_name) = 'chio_governed_approval_replay_source_seal')",
        [],
        |row| row.get(0),
    )?)
}

pub(super) fn barrier_sql() -> String {
    let mut sql = String::new();
    for (name, table) in [
        ("entries", "chio_governed_approval_replay_entries"),
        ("clock", "chio_governed_approval_replay_clock"),
        ("limits", "chio_governed_approval_replay_limits"),
        ("seal", "chio_governed_approval_replay_source_seal"),
    ] {
        for (suffix, operation) in [
            ("insert", "INSERT"),
            ("update", "UPDATE"),
            ("delete", "DELETE"),
        ] {
            sql.push_str(&format!(
                "CREATE TRIGGER chio_governed_approval_replay_source_{name}_no_{suffix}\n\
                 BEFORE {operation} ON {table}\n\
                 BEGIN\n\
                     SELECT RAISE(ABORT, 'governed approval replay source is sealed');\n\
                 END;\n"
            ));
        }
    }
    sql
}

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, Error> {
    let (count, bytes): (i64, i64) = connection.query_row(
        &format!(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(type AS BLOB))
            + length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB))
            + COALESCE(length(CAST(sql AS BLOB)), 0)), 0)
            FROM sqlite_schema WHERE {CATALOG_FILTER}"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if !(0..=64).contains(&count) || !(0..=65_536).contains(&bytes) {
        return Err(invalid("schema exceeds its bounds"));
    }
    let mut statement = connection.prepare(&format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE {CATALOG_FILTER}
         ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY"
    ))?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

fn expected_catalog(sealed: bool) -> Result<Vec<CatalogEntry>, Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(MARKER_SCHEMA)?;
    if sealed {
        connection.execute_batch(SEAL_SCHEMA)?;
        connection.execute_batch(&barrier_sql())?;
    }
    catalog(&connection)
}

pub(super) fn verify(connection: &Connection, sealed: bool) -> Result<(), Error> {
    verify_metadata(connection)?;
    if catalog(connection)? != expected_catalog(sealed)? {
        return Err(invalid("schema differs from its canonical definition"));
    }
    Ok(())
}

/// Migration inspection must never adopt, stamp or repair an unstamped source.
/// The shared legacy startup helper may write application_id, so it is not
/// suitable for preview, exact verification or migration-only reopening.
pub(super) fn verify_metadata(connection: &Connection) -> Result<(), Error> {
    let app_id: i32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if app_id != crate::CHIO_SQLITE_APPLICATION_ID {
        return Err(invalid("source application identity is not canonical"));
    }
    let matches: bool = connection.query_row(
        "SELECT COUNT(*) = 1 AND COALESCE(MIN(typeof(version) = 'integer' AND version = ?2), 0)
         FROM chio_store_schema_versions WHERE store_key = ?1",
        rusqlite::params![
            super::super::GOVERNED_APPROVAL_STORE_SCHEMA_KEY,
            super::super::GOVERNED_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION
        ],
        |row| row.get(0),
    )?;
    if !matches {
        return Err(invalid("source schema version is not canonical"));
    }
    Ok(())
}

pub(super) fn digest() -> Result<String, Error> {
    let bytes = canonical_json_bytes(&expected_catalog(true)?)
        .map_err(|error| invalid(format!("schema encoding failed: {error}")))?;
    Ok(sha256_hex(&bytes))
}
