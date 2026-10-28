use super::*;

#[test]
fn current_source_retains_its_seal_and_rows_across_reopen() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(seeded_security_history(&path)?);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    source.verify_seal(&expected)?;
    let connection = Connection::open(&path)?;
    let seal_before: Vec<u8> = connection.query_row(
        "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("sealed source accepted a writer")?;
    assert_eq!(error, chio_security_types::ports::PortError::retired());
    drop(source);
    let reopened = SqliteSecurityParticipantSource::open(&path)?;
    reopened.verify_seal(&expected)?;
    let retained = reopened.read_sealed_rows(&expected)?;
    assert!(retained.tables.iter().any(|(_, rows)| !rows.is_empty()));
    assert_eq!(
        connection.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        seal_before
    );
    Ok(())
}

#[test]
fn source_refuses_missing_finality_schema_without_repair() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(seeded_security_history(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER security_response_effect_finality_immutable;
         DROP TRIGGER security_response_effect_finality_delete_rejected;
         DROP TABLE security_response_effect_finality;",
    )?;
    let before: i64 = connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
    let error = SqliteSecurityParticipantSource::open(&path)
        .err()
        .ok_or("incomplete finality schema was accepted")?;
    assert!(
        matches!(
            error,
            Error::Invalid("source finality schema is not qualified")
        ),
        "{error}"
    );
    assert_eq!(
        connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))?,
        before
    );
    assert!(!schema::has_evidence(&connection)?);
    Ok(())
}

#[test]
fn sealed_source_with_stale_stamp_cannot_authenticate_its_seal() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(seeded_security_history(&path)?);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    let connection = Connection::open(&path)?;
    let version_trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'chio_security_participant_source_version_no_update'",
        [], |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER chio_security_participant_source_version_no_update")?;
    connection.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state';
         PRAGMA ignore_check_constraints = OFF;",
    )?;
    connection.execute_batch(&version_trigger)?;
    let error = source
        .verify_seal(&expected)
        .err()
        .ok_or("stale stamp authenticated a seal")?;
    assert!(
        matches!(
            error,
            Error::Schema(crate::SchemaVersionError::StaleSchema {
                found: 0,
                current: 1
            })
        ),
        "{error}"
    );
    drop(source);
    let error = SqliteSecurityParticipantSource::open(&path)
        .err()
        .ok_or("stale sealed source was accepted")?;
    assert!(
        matches!(
            error,
            Error::Schema(crate::SchemaVersionError::StaleSchema {
                found: 0,
                current: 1
            })
        ),
        "{error}"
    );
    assert_eq!(
        connection.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        expected.canonical_bytes()?
    );
    Ok(())
}
