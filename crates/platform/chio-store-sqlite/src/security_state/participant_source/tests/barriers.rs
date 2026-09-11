use super::*;

#[test]
fn old_sql_connections_cannot_insert_replace_update_delete_or_relabel_metadata() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    super::declassification::seed_history(&store)?;
    let legacy = Connection::open(&path)?;
    legacy.execute_batch("PRAGMA recursive_triggers = OFF")?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    let count: i64 = legacy.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'trigger'
        AND name GLOB 'chio_security_participant_source_*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 48);
    for table in schema::TABLES
        .iter()
        .chain([&"chio_security_participant_source_seal"])
    {
        for operation in ["INSERT", "INSERT OR IGNORE", "REPLACE"] {
            let error = legacy
                .execute(&format!("{operation} INTO {table} DEFAULT VALUES"), [])
                .err()
                .ok_or("legacy insert was allowed")?;
            assert!(
                error.to_string().contains("source is retired"),
                "{table}: {error}"
            );
        }
        let rows: i64 = legacy.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?;
        if rows != 0 {
            let column: String =
                legacy.query_row(&format!("PRAGMA table_info({table})"), [], |row| row.get(1))?;
            for sql in [
                format!("REPLACE INTO {table} SELECT * FROM {table}"),
                format!("INSERT OR IGNORE INTO {table} SELECT * FROM {table}"),
                format!("UPDATE {table} SET {column} = {column}"),
                format!("DELETE FROM {table}"),
            ] {
                let error = legacy
                    .execute(&sql, [])
                    .err()
                    .ok_or("legacy mutation was allowed")?;
                assert!(
                    error.to_string().contains("source is retired"),
                    "{table}: {error}"
                );
            }
        }
    }
    for sql in [
        "INSERT INTO chio_store_schema_versions VALUES ('SECURITY_STATE', 0)",
        "REPLACE INTO chio_store_schema_versions VALUES ('security_state', 0)",
        "UPDATE chio_store_schema_versions SET store_key = 'renamed' WHERE store_key = 'security_state'",
        "UPDATE chio_store_schema_versions SET version = 1 WHERE store_key = 'security_state'",
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'security_state'",
    ] {
        let error = legacy.execute(sql, []).err().ok_or("legacy metadata mutation was allowed")?;
        assert!(error.to_string().contains("source version is retired"), "{error}");
    }
    source.verify_seal(&expected)?;
    Ok(())
}

#[test]
fn every_partial_seal_or_modified_guard_is_rejected_without_repair() -> TestResult {
    for mutation in [
        "DROP TRIGGER chio_security_participant_source_0_no_insert",
        "DROP TRIGGER chio_security_participant_source_7_no_delete;
         CREATE TRIGGER chio_security_participant_source_7_no_delete BEFORE DELETE ON security_flow_sequences
         BEGIN SELECT 1; END",
        "DROP TRIGGER chio_security_participant_source_14_no_delete;
         DELETE FROM chio_security_participant_source_seal",
        "DROP TRIGGER chio_security_participant_source_14_no_update;
         UPDATE chio_security_participant_source_seal SET canonical_bytes = CAST('{}' AS BLOB)",
        "PRAGMA application_id = 0",
        "CREATE TABLE security_flow_future (value BLOB)",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let _store = seed(&path)?;
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let expected = source.preview(&binding()?)?;
        source.seal_exact(&expected)?;
        let attacker = Connection::open(&path)?;
        attacker.execute_batch(mutation)?;
        let before: i64 = attacker.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        assert!(source.load_seal().is_err(), "{mutation}");
        assert!(source.verify_seal(&expected).is_err());
        assert!(source.seal_exact(&expected).is_err());
        assert!(SqliteSecurityParticipantSource::open(&path).is_err());
        assert!(SqliteSecurityStateStore::open(&path).is_err());
        let after: i64 = attacker.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        assert_eq!(before, after, "invalid retirement must not repair: {mutation}");
    }
    Ok(())
}

#[test]
fn restored_barrier_does_not_hide_a_modified_critical_row() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let _store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    let attacker = Connection::open(&path)?;
    let ddl: String = attacker.query_row(
        "SELECT sql FROM sqlite_schema
        WHERE name = 'chio_security_participant_source_7_no_update'",
        [],
        |row| row.get(0),
    )?;
    attacker.execute_batch(
        "DROP TRIGGER chio_security_participant_source_7_no_update;
        UPDATE security_flow_sequences SET last_generation = last_generation + 1",
    )?;
    attacker.execute_batch(&ddl)?;
    schema::verify(&attacker, true)?;
    assert!(source.load_seal().is_err());
    assert!(source.seal_exact(&expected).is_err());
    assert!(SqliteSecurityParticipantSource::open(&path).is_err());
    Ok(())
}
