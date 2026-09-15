use chio_core::{canonical_json_bytes, sha256_hex};
use rusqlite::{params, Connection};

use super::{Error, Result};

pub(super) const TABLES: &[&str] = &[
    "security_declassification_evidence_identity",
    "security_declassification_lifecycle",
    "security_declassification_receipt_outbox",
    "security_declassification_tombstones",
    "security_declassification_uses",
    "security_egress_fences",
    "security_flow_contexts",
    "security_flow_sequences",
    "security_isolation_epochs",
    "security_lineage_flow_state",
    "security_principal_flow_state",
    "security_session_flow_state",
    "security_session_memberships",
    "security_transitions",
];

pub(super) const SEAL_SCHEMA: &str = r#"
CREATE TABLE chio_security_participant_source_seal (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    canonical_bytes BLOB NOT NULL CHECK (
        typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 65536
    )
);
"#;

const SEAL_NAMESPACE: &str = "lower(name) GLOB '*security_participant_source*'
    OR lower(tbl_name) GLOB '*security_participant_source*'";
type CatalogEntry = (String, String, String, Option<String>);

pub(super) fn has_evidence(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE {SEAL_NAMESPACE})"),
        [],
        |row| row.get(0),
    )?)
}

pub(super) fn barrier_sql() -> String {
    let mut sql = String::new();
    for (index, table) in TABLES
        .iter()
        .chain([&"chio_security_participant_source_seal"])
        .enumerate()
    {
        for (suffix, operation) in [
            ("insert", "INSERT"),
            ("update", "UPDATE"),
            ("delete", "DELETE"),
        ] {
            sql.push_str(&format!(
                "CREATE TRIGGER chio_security_participant_source_{index}_no_{suffix}
                BEFORE {operation} ON {table}
                BEGIN SELECT RAISE(ABORT, 'security participant source is retired'); END;\n"
            ));
        }
    }
    for (suffix, operation, condition) in [
        (
            "insert",
            "INSERT",
            "lower(NEW.store_key) = 'security_state'",
        ),
        (
            "update",
            "UPDATE",
            "lower(OLD.store_key) = 'security_state' OR lower(NEW.store_key) = 'security_state'",
        ),
        (
            "delete",
            "DELETE",
            "lower(OLD.store_key) = 'security_state'",
        ),
    ] {
        sql.push_str(&format!(
            "CREATE TRIGGER chio_security_participant_source_version_no_{suffix}
            BEFORE {operation} ON chio_store_schema_versions WHEN {condition}
            BEGIN SELECT RAISE(ABORT, 'security participant source version is retired'); END;\n"
        ));
    }
    sql
}

fn filter() -> String {
    let tables = TABLES
        .iter()
        .chain([&"chio_store_schema_versions"])
        .map(|table| format!("'{table}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{SEAL_NAMESPACE} OR lower(tbl_name) IN ({tables})
        OR lower(name) GLOB 'security_flow_*'
        OR lower(name) GLOB 'security_declassification_*'
        OR lower(name) GLOB 'security_egress_fences*'
        OR lower(name) GLOB 'security_isolation_epochs*'
        OR lower(name) GLOB 'security_*flow_state*'
        OR lower(name) GLOB 'security_session_memberships*'
        OR lower(name) GLOB 'security_transitions*'"
    )
}

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>> {
    let filter = filter();
    let (count, bytes): (i64, i64) = connection.query_row(
        &format!(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(type AS BLOB)) + length(CAST(name AS BLOB))
        + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)), 0)), 0)
        FROM sqlite_schema WHERE {filter}"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if !(0..=192).contains(&count) || !(0..=262_144).contains(&bytes) {
        return Err(Error::Invalid("source catalog exceeds bounds"));
    }
    let mut statement = connection.prepare(&format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE {filter}
        ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY"
    ))?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn expected_catalog(sealed: bool) -> Result<Vec<CatalogEntry>> {
    let connection = Connection::open_in_memory()?;
    // Construct only a disposable model catalog. Never normalize the source.
    super::super::migrate(&connection)
        .map_err(|_| Error::Invalid("canonical security catalog is unavailable"))?;
    if sealed {
        connection.execute_batch(SEAL_SCHEMA)?;
        connection.execute_batch(&barrier_sql())?;
    }
    catalog(&connection)
}

pub(super) fn verify(connection: &Connection, sealed: bool) -> Result<()> {
    if catalog(connection)? != expected_catalog(sealed)? {
        return Err(Error::Invalid(
            "source catalog is not the exact qualified predecessor",
        ));
    }
    let app_id: i32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if app_id != crate::CHIO_SQLITE_APPLICATION_ID {
        return Err(Error::Invalid(
            "source application identity is not canonical",
        ));
    }
    let valid: bool = connection.query_row(
        "SELECT COUNT(*) = 1 AND COALESCE(MIN(store_key = 'security_state'
        AND typeof(version) = 'integer' AND version = ?1), 0)
        FROM chio_store_schema_versions WHERE lower(store_key) = 'security_state'",
        params![super::super::SECURITY_STATE_STORE_SUPPORTED_SCHEMA_VERSION],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(Error::Invalid(
            "source security schema version is not canonical",
        ));
    }
    Ok(())
}

pub(super) fn digest() -> Result<String> {
    let mut bytes = b"chio.security-participant-source.catalog.v1\0".to_vec();
    bytes.extend(
        canonical_json_bytes(&expected_catalog(true)?)
            .map_err(|_| Error::Invalid("source catalog cannot be encoded"))?,
    );
    Ok(sha256_hex(&bytes))
}
