use super::*;

#[test]
fn v26_upgrade_is_empty_and_rejects_partial_future_or_aliased_state_without_repair(
) -> AnchoredTestResult {
    for damage in [
        None,
        Some("CREATE TABLE security_participant_migration_future(value TEXT)"),
        Some("CREATE TABLE SECURITY_PARTICIPANT_MIGRATION_alias(value TEXT)"),
        Some("DROP TRIGGER admission_operation_commits_immutable"),
    ] {
        let fixture = fixture();
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        remove_empty_v27_tables(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 26 WHERE store_key = 'admission_operation'")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        let head: (i64, String) = connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        drop(connection);
        let result = SqliteAuthorityStore::provision(&database, &lock_root);
        let connection = Connection::open(&database)?;
        let version: i32 = connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get(0))?;
        assert_eq!(connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?, head);
        if damage.is_some() {
            assert!(result.is_err());
            assert_eq!(version, 26);
            assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_participant_migration_expectations'", [], |row| row.get::<_, i64>(0))?, 0);
        } else {
            result?;
            assert_eq!(version, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
            assert_eq!(
                connection.query_row(
                    "SELECT COUNT(*) FROM security_participant_migration_expectations",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        }
    }
    Ok(())
}

#[test]
fn current_schema_with_missing_migration_barrier_is_not_repaired() -> AnchoredTestResult {
    let fixture = fixture();
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    connection.execute_batch("DROP TRIGGER security_participant_migration_rows_no_replace")?;
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_participant_migration_rows_no_replace'", [], |row| row.get::<_, i64>(0))?, 0);
    Ok(())
}
