use super::*;

#[test]
fn v22_upgrade_preserves_imported_approval_bytes_and_rejects_unqualified_claims(
) -> AnchoredTestResult {
    for damage in [
        None,
        Some("CREATE TABLE governed_approval_replay_claim_unknown(value TEXT)"),
        Some("DROP TRIGGER governed_approval_replay_migration_events_immutable"),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
        let count = global_count(&fixture);
        drop(source);
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
        remove_empty_v23_claim_tables(&connection)?;
        connection.execute_batch("DROP TRIGGER governed_approval_replay_migration_events_no_replace;
            DROP TRIGGER governed_approval_replay_migration_events_immutable;
            DROP TRIGGER governed_approval_replay_migration_events_no_delete;
            ALTER TABLE governed_approval_replay_migration_events RENAME TO approval_events_v23_fixture;")?;
        connection.execute_batch(
            &crate::admission_operation_store::schema::pre_approval_activation_schema_fixture(),
        )?;
        connection.execute_batch("INSERT INTO governed_approval_replay_migration_events SELECT * FROM approval_events_v23_fixture;
            DROP TABLE approval_events_v23_fixture;
            UPDATE chio_store_schema_versions SET version = 22 WHERE store_key = 'admission_operation';")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        drop(connection);
        let result = SqliteAuthorityStore::provision(&database, &lock_root);
        if damage.is_some() {
            assert!(result.is_err());
            let connection = Connection::open(&database)?;
            assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, 22);
        } else {
            result?;
            let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
            let store = authority.admission_operation_store();
            assert_eq!(
                store.load_governed_approval_replay_migration(
                    &identifier("authority", AUTHORITY_ID),
                    &authority.mutation_fence(),
                    now_ms()
                )?,
                Some(imported)
            );
            let connection = store.connection()?;
            assert_eq!(
                connection.query_row(
                    "SELECT COUNT(*) FROM authority_global_commits",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                count
            );
            assert_eq!(
                connection.query_row(
                    "SELECT COUNT(*) FROM governed_approval_replay_claim_episodes",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            verify_admission_operation_invariants(&connection)?;
        }
    }
    Ok(())
}

#[test]
fn v21_upgrade_introduces_only_empty_approval_history_and_rejects_unqualified_namespaces(
) -> AnchoredTestResult {
    for damage in [
        None,
        Some("CREATE TABLE governed_approval_replay_unknown(value TEXT)"),
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
        remove_empty_v22_approval_tables(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 21 WHERE store_key = 'admission_operation'")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        drop(connection);
        let result = SqliteAuthorityStore::provision(&database, &lock_root);
        let connection = Connection::open(&database)?;
        let version: i32 = connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get(0))?;
        if damage.is_some() {
            assert!(result.is_err());
            assert_eq!(version, 21);
            assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'governed_approval_replay_migration_expectations'", [], |row| row.get::<_, i64>(0))?, 0);
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
        }
    }
    Ok(())
}
