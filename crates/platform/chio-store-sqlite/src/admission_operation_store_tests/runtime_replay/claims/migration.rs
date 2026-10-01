use super::*;

#[test]
fn populated_v19_upgrade_preserves_exact_commits_anchors_and_imported_source() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, false)?;
    let (operation, _) = setup(&fixture, "v19-history")?;
    let (head, commits) = {
        let connection = fixture.store.connection()?;
        (
            load_admission_commit_head(&connection)?,
            commit_rows(&connection)?,
        )
    };
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
    let mut connection = Connection::open(&database)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA legacy_alter_table = ON")?;
    {
        let transaction = connection.transaction()?;
        for table in [
            "runtime_replay_claim_releases",
            "runtime_replay_claim_resources",
            "runtime_replay_claim_episodes",
        ] {
            let count: i64 =
                transaction.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 0, "the v19 fixture cannot discard claim history");
            transaction.execute_batch(&format!("DROP TABLE {table}"))?;
        }
        transaction.execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
             DROP TRIGGER admission_operation_commits_immutable;
             DROP TRIGGER admission_operation_commits_no_delete;
             DROP INDEX admission_operation_commits_operation;
             ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v20_fixture;"
        )?;
        let schema = crate::admission_operation_store::schema::pre_runtime_claim_schema_fixture();
        transaction.execute_batch(&schema)?;
        transaction.execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
             INSERT INTO admission_operation_commits SELECT * FROM admission_operation_commits_v20_fixture;
             DROP TABLE admission_operation_commits_v20_fixture;"
        )?;
        transaction.execute_batch(&schema)?;
        downgrade_runtime_events(&transaction)?;
        transaction.execute_batch("UPDATE chio_store_schema_versions SET version = 19 WHERE store_key = 'admission_operation'")?;
        transaction.commit()?;
    }
    assert_eq!(commit_rows(&connection)?, commits);
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    assert_eq!(
        store.load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    assert_eq!(
        store.load_runtime_replay_migration(
            &identifier("runtime", RUNTIME_ID),
            &reopened.mutation_fence(),
            now_ms()
        )?,
        Some(source)
    );
    let connection = store.connection()?;
    assert_eq!(load_admission_commit_head(&connection)?, head);
    assert_eq!(commit_rows(&connection)?, commits);
    verify_admission_operation_invariants(&connection)?;
    assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
    Ok(())
}

fn downgrade_runtime_events(connection: &Connection) -> TestResult {
    crate::admission_operation_store::tests::governed_approval_replay::remove_empty_v22_approval_tables(connection)?;
    let active: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_replay_migration_events WHERE sequence > 2)",
        [],
        |row| row.get(0),
    )?;
    assert!(
        !active,
        "the predecessor fixture cannot discard activation history"
    );
    connection.execute_batch(
        "DROP TRIGGER runtime_replay_migration_events_no_replace;
         DROP TRIGGER runtime_replay_migration_events_immutable;
         DROP TRIGGER runtime_replay_migration_events_no_delete;
         ALTER TABLE runtime_replay_migration_events RENAME TO runtime_events_v21_fixture;",
    )?;
    connection.execute_batch(
        &crate::admission_operation_store::schema::pre_runtime_activation_schema_fixture(),
    )?;
    connection.execute_batch(
        "INSERT INTO runtime_replay_migration_events SELECT * FROM runtime_events_v21_fixture;
         DROP TABLE runtime_events_v21_fixture;",
    )?;
    Ok(())
}

fn commit_rows(connection: &Connection) -> rusqlite::Result<Vec<Vec<Value>>> {
    let mut statement =
        connection.prepare("SELECT * FROM admission_operation_commits ORDER BY commit_sequence")?;
    let columns = statement.column_count();
    let rows = statement.query_map([], |row| {
        (0..columns).map(|column| row.get(column)).collect()
    })?;
    rows.collect()
}

#[test]
fn populated_v20_upgrade_preserves_claims_releases_and_global_history() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, false)?;
    let (operation, lease) = setup(&fixture, "v20-owned-history")?;
    let candidate = intent(
        &operation,
        &source,
        "first",
        &[(Kind::DestructiveLease, "owned")],
    )?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    let lease = renew(&fixture, &operation, &lease)?;
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    let candidate = intent(
        &operation,
        &source,
        "second",
        &[(Kind::DestructiveLease, "owned")],
    )?;
    let (operation, _) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    let before = fixture.store.load_runtime_participant_history(
        operation.binding().operation_id(),
        &fixture.fence,
        now_ms(),
    )?;
    let tables = [
        "admission_operation_commits",
        "runtime_replay_migration_events",
        "runtime_replay_legacy_tombstones",
        "runtime_replay_claim_episodes",
        "runtime_replay_claim_resources",
        "runtime_replay_claim_releases",
        "authority_global_commits",
    ];
    let rows_before = {
        let connection = fixture.store.connection()?;
        tables
            .iter()
            .map(|table| table_rows(&connection, table))
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
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
    let mut connection = Connection::open(&database)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA legacy_alter_table = ON")?;
    {
        let transaction = connection.transaction()?;
        downgrade_runtime_events(&transaction)?;
        transaction.execute_batch("UPDATE chio_store_schema_versions SET version = 20 WHERE store_key = 'admission_operation'")?;
        transaction.commit()?;
    }
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    // Inspect the migration before a new serving lease adds its own global history.
    {
        let connection = Connection::open(&database)?;
        for (table, expected) in tables.iter().zip(&rows_before) {
            assert_eq!(&table_rows(&connection, table)?, expected, "{table}");
        }
        assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
    }
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert_eq!(
        store.load_runtime_participant_history(
            operation.binding().operation_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        before
    );
    assert_eq!(
        store.load_runtime_replay_migration(
            &identifier("runtime", RUNTIME_ID),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(source)
    );
    Ok(())
}

fn table_rows(connection: &Connection, table: &str) -> rusqlite::Result<Vec<Vec<Value>>> {
    let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
    let columns = statement.column_count();
    let rows = statement.query_map([], |row| {
        (0..columns).map(|column| row.get(column)).collect()
    })?;
    rows.collect()
}
