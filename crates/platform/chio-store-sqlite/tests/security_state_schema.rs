use std::error::Error as _;

use chio_security_types::ports::{PortError, PortErrorKind};
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::SqliteSecurityStateStore;
use rusqlite::Connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn catalog(connection: &Connection) -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
    connection
        .prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect()
}

fn stale_schema(error: &PortError) {
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code().as_str(), "store.integrity_failure");
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("database schema version 0 is not the current schema version 1; refusing to open")
    );
}

#[test]
fn stamped_zero_is_refused_without_catalog_mutation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(SqliteSecurityStateStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER security_response_effect_finality_immutable;
         DROP TRIGGER security_response_effect_finality_delete_rejected;
         DROP TABLE security_response_effect_finality;
         UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state';",
    )?;
    let before = catalog(&connection)?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("stamped zero was accepted")?;
    stale_schema(&error);
    assert_eq!(catalog(&connection)?, before);
    assert_eq!(
        connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
            [],
            |row| row.get::<_, i32>(0),
        )?,
        0
    );
    Ok(())
}

#[test]
fn source_with_zero_stamp_is_refused_without_catalog_mutation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(SqliteSecurityStateStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER security_response_effect_finality_immutable;
         DROP TRIGGER security_response_effect_finality_delete_rejected;
         DROP TABLE security_response_effect_finality;
         UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state';",
    )?;
    let before = catalog(&connection)?;
    let error = SqliteSecurityParticipantSource::open(&path)
        .err()
        .ok_or("source with zero stamp was accepted")?;
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("database schema version 0 is not the current schema version 1; refusing to open")
    );
    assert_eq!(catalog(&connection)?, before);
    Ok(())
}

#[test]
fn missing_security_stamp_is_refused_without_catalog_mutation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(SqliteSecurityStateStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'security_state'",
        [],
    )?;
    let before = catalog(&connection)?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("security namespace without a stamp was accepted")?;
    stale_schema(&error);
    assert_eq!(catalog(&connection)?, before);
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM chio_store_schema_versions WHERE store_key = 'security_state'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    Ok(())
}

#[test]
fn current_stamp_with_noncanonical_key_is_refused_without_mutation() -> TestResult {
    for damage in [
        "INSERT INTO chio_store_schema_versions (store_key, version) VALUES ('SECURITY_STATE', 2);",
        "ALTER TABLE chio_store_schema_versions RENAME TO saved_stamps;
         CREATE TABLE chio_store_schema_versions (
             store_key TEXT COLLATE NOCASE NOT NULL PRIMARY KEY,
             version INTEGER NOT NULL
         );
         INSERT INTO chio_store_schema_versions
             SELECT CASE WHEN store_key = 'security_state' THEN 'SECURITY_STATE' ELSE store_key END,
                    version FROM saved_stamps;
         DROP TABLE saved_stamps;",
    ] {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("security.db");
        drop(SqliteSecurityStateStore::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(damage)?;
        let before = catalog(&connection)?;
        let stamps = || -> rusqlite::Result<Vec<(String, i32)>> {
            connection
                .prepare(
                    "SELECT store_key, version FROM chio_store_schema_versions ORDER BY store_key",
                )?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        };
        let stamps_before = stamps()?;
        let error = SqliteSecurityStateStore::open(&path)
            .err()
            .ok_or("noncanonical security schema stamp was accepted")?;
        assert_eq!(error, PortError::integrity_failure());
        assert_eq!(catalog(&connection)?, before);
        assert_eq!(stamps()?, stamps_before);
    }
    Ok(())
}

#[test]
fn current_stamp_with_replaced_lifecycle_shape_is_refused_without_repair() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(SqliteSecurityStateStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "DROP TABLE security_declassification_lifecycle;
         CREATE TABLE security_declassification_lifecycle (
             singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL CHECK (schema_version = 2),
             readiness_cursor TEXT NOT NULL,
             reconciliation_active INTEGER NOT NULL DEFAULT 0
                 CHECK (reconciliation_active IN (0, 1)),
             live_dispatch_sealed INTEGER NOT NULL DEFAULT 0
                 CHECK (live_dispatch_sealed IN (0, 1)),
             compaction_active INTEGER NOT NULL DEFAULT 0
                 CHECK (compaction_active IN (0, 1)),
             CHECK (reconciliation_active = 0 OR live_dispatch_sealed = 0)
         );
         INSERT INTO security_declassification_lifecycle
             (singleton, schema_version, readiness_cursor)
         VALUES (1, 2, 'declassification-evidence-schema-v2');",
    )?;
    let before = catalog(&connection)?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("replaced lifecycle shape was accepted")?;
    assert_eq!(error, PortError::integrity_failure());
    assert_eq!(catalog(&connection)?, before);
    Ok(())
}

#[test]
fn unstamped_populated_schema_is_refused_without_catalog_mutation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TABLE security_scheduler_retries (
             tenant_id TEXT NOT NULL,
             action_id TEXT NOT NULL,
             attempts INTEGER NOT NULL,
             last_error TEXT NOT NULL,
             not_before INTEGER NOT NULL,
             PRIMARY KEY (tenant_id, action_id)
         );
         INSERT INTO security_scheduler_retries VALUES ('tenant-a', 'action-a', 3, 'store.unavailable', 1234);",
    )?;
    let before = catalog(&connection)?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("unstamped populated schema was accepted")?;
    assert_eq!(error, PortError::integrity_failure());
    assert_eq!(catalog(&connection)?, before);
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    assert_eq!(
        connection.query_row(
            "SELECT attempts FROM security_scheduler_retries",
            [],
            |row| { row.get::<_, i64>(0) }
        )?,
        3
    );
    Ok(())
}

#[test]
fn current_stamp_with_incomplete_schema_is_refused_without_repair() -> TestResult {
    for damage in [
        "DROP TABLE security_declassification_lifecycle;",
        "DROP TRIGGER security_response_automatic_preparations_immutable;
         DROP TRIGGER security_response_automatic_preparations_delete_rejected;
         DROP TABLE security_response_automatic_preparations;",
        "DROP TABLE security_attested_finding_response_outbox;",
        "ALTER TABLE security_scheduler_leases DROP COLUMN lease_body_hash;",
        "ALTER TABLE security_scheduler_retries DROP COLUMN first_failure_at;",
        "ALTER TABLE security_response_effects DROP COLUMN generation;",
        "ALTER TABLE security_response_dispatches DROP COLUMN commit_mode;",
        "ALTER TABLE security_lineage_fences DROP COLUMN scheduler_lease_owner_id;",
        "DROP INDEX security_correlation_ingress_pending;
         CREATE INDEX security_correlation_ingress_pending ON security_correlation_ingress (acknowledged, sequence);",
    ] {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("security.db");
        drop(SqliteSecurityStateStore::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(damage)?;
        let before = catalog(&connection)?;
        let error = SqliteSecurityStateStore::open(&path)
            .err()
            .ok_or("incomplete schema was accepted")?;
        assert_eq!(error, PortError::integrity_failure(), "{damage}");
        assert_eq!(catalog(&connection)?, before, "{damage}");
    }
    Ok(())
}
