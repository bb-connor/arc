use super::*;

#[test]
fn opening_refuses_missing_uri_memory_symlink_hardlink_and_replaced_paths() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    assert!(SqliteSecurityParticipantSource::open(&path).is_err());
    assert!(!path.exists());
    for uri in [
        ":memory:",
        "file:security.db",
        "security.db?mode=rw",
        "security.db#fragment",
        "",
    ] {
        assert!(SqliteSecurityParticipantSource::open(uri).is_err());
    }
    let _store = seed(&path)?;
    let alias = directory.path().join("alias.db");
    std::os::unix::fs::symlink(&path, &alias)?;
    assert!(SqliteSecurityParticipantSource::open(&alias).is_err());
    let link = directory.path().join("hardlink.db");
    std::fs::hard_link(&path, &link)?;
    assert!(SqliteSecurityParticipantSource::open(&path).is_err());
    assert!(SqliteSecurityParticipantSource::open(&link).is_err());
    Ok(())
}

#[test]
fn open_handle_rejects_a_path_replaced_with_another_real_sqlite_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    drop(store);
    let second = directory.path().join("replacement.db");
    drop(seed(&second)?);
    std::fs::rename(&path, directory.path().join("retained-original.db"))?;
    std::fs::rename(&second, &path)?;
    assert!(source.preview(&binding()?).is_err());
    assert!(source.seal_exact(&expected).is_err());
    assert!(!schema::has_evidence(&Connection::open(&path)?)?);
    Ok(())
}

#[test]
fn a_byte_copy_cannot_recreate_the_original_physical_source_seal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    drop(source);
    drop(store);
    let copy = directory.path().join("copy.db");
    std::fs::copy(&path, &copy)?;
    assert!(SqliteSecurityParticipantSource::open(&copy).is_err());
    SqliteSecurityParticipantSource::open(&path)?.verify_seal(&expected)?;
    Ok(())
}

#[test]
fn unqualified_source_open_never_normalizes_catalog_or_version_evidence() -> TestResult {
    for mutation in [
        "PRAGMA application_id = 0",
        "UPDATE chio_store_schema_versions SET version = 1 WHERE store_key = 'security_state'",
        "UPDATE chio_store_schema_versions SET store_key = 'SECURITY_STATE' WHERE store_key = 'security_state'",
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'security_state'",
        "CREATE TABLE security_flow_future (value BLOB)",
        "CREATE TABLE chio_security_participant_source_unrecognized (value BLOB)",
        "DROP INDEX security_declassification_receipt_pending",
        "DELETE FROM security_declassification_lifecycle",
        "UPDATE security_declassification_lifecycle SET compaction_active = 1",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        drop(seed(&path)?);
        let legacy = Connection::open(&path)?;
        legacy.execute_batch(mutation)?;
        let before: i64 = legacy.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let version: i64 = legacy.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        assert!(SqliteSecurityParticipantSource::open(&path).is_err(), "{mutation}");
        assert_eq!(legacy.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))?, before);
        assert_eq!(legacy.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))?, version);
    }
    Ok(())
}

#[test]
fn oversized_row_count_cell_and_invalid_flow_labels_fail_closed() -> TestResult {
    for mutation in [
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 16385)
         INSERT INTO security_flow_sequences SELECT 'excess-' || x, x FROM n",
        "INSERT INTO security_flow_sequences VALUES (zeroblob(1048577), 1)",
        "UPDATE security_principal_flow_state SET label_hash = zeroblob(32)",
        "UPDATE security_flow_contexts SET generation = 0",
        "INSERT INTO security_flow_sequences VALUES ('real-number', 1.5)",
        "INSERT INTO security_flow_sequences VALUES (CAST(x'ff' AS TEXT), 1)",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let _store = seed(&path)?;
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let legacy = Connection::open(&path)?;
        legacy.execute_batch(mutation)?;
        assert!(source.preview(&binding()?).is_err(), "{mutation}");
        assert!(SqliteSecurityParticipantSource::open(&path).is_err());
        assert!(!schema::has_evidence(&legacy)?);
    }
    Ok(())
}

#[test]
fn source_requires_wal_and_rechecks_full_synchronous_at_each_observation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    drop(seed(&path)?);
    let legacy = Connection::open(&path)?;
    legacy.execute_batch("PRAGMA journal_mode = DELETE")?;
    assert!(SqliteSecurityParticipantSource::open(&path).is_err());
    let mode: String = legacy.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(
        mode, "delete",
        "open must not normalize durability settings"
    );
    legacy.execute_batch("PRAGMA journal_mode = WAL")?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    {
        let connection = source
            .connection
            .lock()
            .map_err(|_| "source mutex poisoned")?;
        connection.execute_batch("PRAGMA synchronous = NORMAL")?;
    }
    assert!(source.preview(&binding()?).is_err());
    assert!(source.load_seal().is_err());
    assert!(source.seal_exact(&expected).is_err());
    assert!(!schema::has_evidence(&legacy)?);
    Ok(())
}
