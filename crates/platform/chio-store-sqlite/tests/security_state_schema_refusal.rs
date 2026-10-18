use chio_security_types::ports::PortErrorKind;
use chio_store_sqlite::SqliteSecurityStateStore;
use rusqlite::Connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_refused_without_repair(damage: &str) -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(SqliteSecurityStateStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute_batch(damage)?;
    let snapshot = || -> rusqlite::Result<_> {
        let catalog = connection
            .prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let stamps = connection
            .prepare(
                "SELECT store_key, version FROM chio_store_schema_versions ORDER BY store_key",
            )?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((catalog, stamps))
    };
    let before = snapshot()?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("noncanonical security schema was accepted")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code().as_str(), "store.integrity_failure");
    assert_eq!(snapshot()?, before);
    Ok(())
}

#[test]
fn zero_revision_is_refused_without_finality_backfill() -> TestResult {
    assert_refused_without_repair(
        "DROP TRIGGER security_response_effect_finality_immutable;
         DROP TRIGGER security_response_effect_finality_delete_rejected;
         DROP TABLE security_response_effect_finality;
         UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state';",
    )
}

#[test]
fn absent_lease_hash_column_is_refused_without_repair() -> TestResult {
    assert_refused_without_repair(
        "ALTER TABLE security_scheduler_leases DROP COLUMN lease_body_hash;",
    )
}

#[test]
fn absent_retry_health_column_is_refused_without_repair() -> TestResult {
    assert_refused_without_repair(
        "ALTER TABLE security_scheduler_retries DROP COLUMN health_event_id;",
    )
}

#[test]
fn absent_outbox_trigger_is_refused_without_repair() -> TestResult {
    assert_refused_without_repair(
        "DROP TRIGGER security_attested_finding_response_outbox_immutable;",
    )
}
