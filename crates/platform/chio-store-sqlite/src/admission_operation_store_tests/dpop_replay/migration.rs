use super::*;

#[test]
fn v23_upgrade_adds_only_empty_dpop_history_and_rejects_unqualified_namespaces(
) -> AnchoredTestResult {
    for damage in [
        None,
        Some("CREATE TABLE dpop_replay_unqualified(value TEXT)"),
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
        remove_empty_v24_tables(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 23 WHERE store_key = 'admission_operation'")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        drop(connection);
        let result = SqliteAuthorityStore::provision(&database, &lock_root);
        let connection = Connection::open(&database)?;
        let version: i32 = connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get(0))?;
        if damage.is_some() {
            assert!(result.is_err());
            assert_eq!(version, 23);
            assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'dpop_replay_migration_expectations'", [], |row| row.get::<_, i64>(0))?, 0);
        } else {
            result?;
            assert_eq!(
                version,
                crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION
            );
            for table in TABLES {
                assert_eq!(
                    connection
                        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                            .get::<_, i64>(0))?,
                    0
                );
            }
            SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        }
    }
    Ok(())
}
