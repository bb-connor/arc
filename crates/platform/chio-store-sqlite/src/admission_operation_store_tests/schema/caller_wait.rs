//! Populated v33 upgrade preserves original operation, recovery ownership and
//! append-only commit bytes. This constructs only disposable predecessor files.
use super::*;

/// Build a genuine predecessor in a disposable fixture, preserving all rows
/// and parent names. Refuse to erase an authenticated caller's retained wait.
pub(in crate::admission_operation_store::tests) fn remove_caller_wait_state(
    connection: &Connection,
) -> rusqlite::Result<()> {
    let foreign_keys: bool =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let legacy_alter: bool =
        connection.pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    if !connection.is_autocommit() {
        assert!(
            !foreign_keys && legacy_alter,
            "nested fixture must preserve parent names"
        );
        return rebuild_predecessor(connection);
    }
    let result = (|| {
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "legacy_alter_table", true)?;
        let tx = connection.unchecked_transaction()?;
        rebuild_predecessor(&tx)?;
        tx.commit()
    })();
    let restore_foreign = connection.pragma_update(None, "foreign_keys", foreign_keys);
    let restore_legacy = connection.pragma_update(None, "legacy_alter_table", legacy_alter);
    result?;
    restore_foreign?;
    restore_legacy
}

fn rebuild_predecessor(connection: &Connection) -> rusqlite::Result<()> {
    remove_empty_checkpoint_catalog(connection)?;
    remove_empty_recovery_schema(connection)?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM admission_operations WHERE state = 'awaiting_caller_report'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0,
        "predecessor fixture cannot discard caller wait custody"
    );
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'admission_operations'",
        [],
        |row| row.get(0),
    )?;
    if !sql.contains("'awaiting_caller_report'") {
        return Ok(());
    }
    connection.execute_batch(
        "DROP INDEX admission_operations_replay_key;
        DROP INDEX admission_operations_request_id;
        DROP INDEX admission_operations_recovery;
        DROP TRIGGER admission_operations_immutable_identity;
        DROP TRIGGER admission_operations_versioned_body;
        DROP TRIGGER admission_operations_terminal_immutable;
        DROP TRIGGER admission_operations_no_delete;
        DROP TRIGGER admission_operations_terminal_no_claim;
        DROP TRIGGER admission_operations_commit_threshold_approval;
        DROP TRIGGER admission_operations_cancel_threshold_approval;
        ALTER TABLE admission_operations RENAME TO admission_operations_v34_fixture;",
    )?;
    connection.execute_batch(
        &crate::admission_operation_store::schema::pre_caller_wait_schema_fixture(),
    )?;
    connection.execute_batch(
        "INSERT INTO admission_operations SELECT * FROM admission_operations_v34_fixture;
        DROP TABLE admission_operations_v34_fixture;",
    )
}

pub(in crate::admission_operation_store::tests) fn remove_empty_checkpoint_catalog(
    connection: &Connection,
) -> rusqlite::Result<()> {
    for table in [
        "security_participant_checkpoint_rows",
        "security_participant_checkpoint_events",
    ] {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            continue;
        }
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            count, 0,
            "predecessor fixture cannot discard checkpoint history"
        );
        connection.execute_batch(&format!("DROP TABLE {table}"))?;
    }
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'security_participant_checkpoint'",[],|row|row.get::<_,i64>(0))?,0,
        "predecessor fixture cannot discard checkpoint references");
    Ok(())
}

fn remove_empty_recovery_schema(connection: &Connection) -> rusqlite::Result<()> {
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'admission_operation_recovery_deferrals')",[],|row|row.get(0))?;
    if exists {
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM admission_operation_recovery_deferrals",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0,
            "predecessor fixture cannot discard recovery deferrals"
        );
    }
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM admission_operation_commits WHERE mutation_kind IN ('recovery_deferred','recovery_deferral_cleared')",[],|row|row.get::<_,i64>(0))?,0,
        "predecessor fixture cannot discard recovery commit evidence");
    if exists {
        connection.execute_batch("DROP TABLE admission_operation_recovery_deferrals")?;
    }
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'admission_operation_commits'",
        [],
        |row| row.get(0),
    )?;
    if !sql.contains("'recovery_deferred'") {
        return Ok(());
    }
    connection.execute_batch(
        "DROP TRIGGER admission_operation_commits_exact_lease;
        DROP TRIGGER admission_operation_commits_immutable;
        DROP TRIGGER admission_operation_commits_no_delete;
        DROP INDEX admission_operation_commits_operation;
        ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v35_fixture;",
    )?;
    let model = crate::admission_operation_store::schema::pre_recovery_schema_fixture();
    connection.execute_batch(&model)?;
    connection.execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;
        INSERT INTO admission_operation_commits SELECT * FROM admission_operation_commits_v35_fixture;
        DROP TABLE admission_operation_commits_v35_fixture;")?;
    connection.execute_batch(&model)
}

fn rows(connection: &Connection, table: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    assert!(matches!(
        table,
        "admission_operations" | "admission_operation_commits"
    ));
    let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let columns = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn populated_v33_caller_wait_upgrade_preserves_original_rows_and_commit_chain() -> AnchoredTestResult
{
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "v33-retained-operation",
        "v33-original-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    let _lease = claim(
        &fixture,
        &operation,
        "v33-original-recovery-owner",
        now_ms(),
    );
    let (before_operations, before_commits) = {
        let connection = fixture.store.connection()?;
        (
            rows(&connection, "admission_operations")?,
            rows(&connection, "admission_operation_commits")?,
        )
    };
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    remove_caller_wait_state(&connection)?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 33 WHERE store_key = 'admission_operation';")?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    assert_eq!(
        rows(&connection, "admission_operations")?,
        before_operations
    );
    assert_eq!(
        rows(&connection, "admission_operation_commits")?,
        before_commits
    );
    assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
    let bad_foreign_key: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |row| row.get(0),
    )?;
    assert!(!bad_foreign_key);
    drop(connection);
    let reopened = crate::test_authority::open_serving(&database, &lock_root)?;
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

fn retained_versioned_rows(
    connection: &Connection,
    table: &str,
) -> rusqlite::Result<Vec<Vec<Value>>> {
    let order = match table {
        "admission_operations" => "operation_id",
        "admission_operation_commits" | "authority_global_commits" => "commit_sequence",
        "admission_operation_commit_meta" | "authority_global_commit_meta" => "singleton",
        _ => panic!("unexpected historical fixture table"),
    };
    let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
    let columns = statement.column_count();
    let result = statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect();
    result
}

/// Rebuild only the commit table's compiled historical objects. All populated
/// operation/commit rows stay byte-identical, and parent names are preserved.
fn rebuild_versioned_commits(connection: &Connection, ddl: &str) -> rusqlite::Result<()> {
    let compiled = Connection::open_in_memory()?;
    compiled.execute_batch(ddl)?;
    let mut statement = compiled.prepare(
        "SELECT sql FROM sqlite_schema WHERE tbl_name = 'admission_operation_commits'
         AND sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name",
    )?;
    let objects = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let exact_lease_guard: String = compiled.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
         AND name = 'admission_operation_commits_exact_lease'",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(
        "DROP TRIGGER admission_operation_commits_exact_lease;
         DROP TRIGGER admission_operation_commits_immutable;
         DROP TRIGGER admission_operation_commits_no_delete;
         DROP INDEX admission_operation_commits_operation;
         ALTER TABLE admission_operation_commits RENAME TO admission_commits_versioned_fixture;",
    )?;
    for object in &objects {
        connection.execute_batch(object)?;
    }
    connection.execute_batch(
        "DROP TRIGGER admission_operation_commits_exact_lease;
         INSERT INTO admission_operation_commits SELECT * FROM admission_commits_versioned_fixture ORDER BY commit_sequence;
         DROP TABLE admission_commits_versioned_fixture;",
    )?;
    connection.execute_batch(&exact_lease_guard)
}

fn shape_versioned_predecessor(connection: &mut Connection, version: i32) -> rusqlite::Result<()> {
    let foreign: bool = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let legacy: bool =
        connection.pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    let result = (|| {
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "legacy_alter_table", true)?;
        let tx = connection.transaction()?;
        match version {
            18 | 19 => {
                crate::admission_operation_store::tests::runtime_replay::remove_empty_v19_runtime_tables(&tx)?;
                rebuild_versioned_commits(
                    &tx,
                    &crate::admission_operation_store::schema::pre_runtime_claim_schema_fixture(),
                )?;
                if version == 19 {
                    tx.execute_batch(&crate::admission_operation_store::schema::pre_runtime_activation_schema_fixture())?;
                }
            }
            20 => {
                crate::admission_operation_store::tests::governed_approval_replay::remove_empty_v22_approval_tables(&tx)?;
                assert_eq!(
                    tx.query_row(
                        "SELECT COUNT(*) FROM runtime_replay_migration_events",
                        [],
                        |row| row.get::<_, i64>(0)
                    )?,
                    0,
                    "historical fixture cannot discard runtime activation history"
                );
                tx.execute_batch("DROP TABLE runtime_replay_migration_events")?;
                tx.execute_batch(&crate::admission_operation_store::schema::pre_runtime_activation_schema_fixture())?;
            }
            23..=25 => {
                crate::admission_operation_store::tests::dpop_replay::remove_empty_v24_tables(&tx)?;
                if version == 24 {
                    tx.execute_batch(&crate::admission_operation_store::schema::pre_dpop_activation_schema_fixture())?;
                } else if version == 25 {
                    tx.execute_batch(
                        crate::admission_operation_store::DPOP_REPLAY_MIGRATION_SCHEMA,
                    )?;
                    tx.execute_batch(crate::admission_operation_store::DPOP_AUTHORITY_SCHEMA)?;
                }
            }
            _ => panic!("unsupported historical fixture version"),
        }
        tx.execute(
            "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = 'admission_operation'",
            [version],
        )?;
        tx.commit()
    })();
    let restore_foreign = connection.pragma_update(None, "foreign_keys", foreign);
    let restore_legacy = connection.pragma_update(None, "legacy_alter_table", legacy);
    result?;
    restore_foreign?;
    restore_legacy
}

#[test]
fn public_historical_catalog_upgrades_preserve_nonempty_rows_and_anchors() -> AnchoredTestResult {
    let tables = [
        "admission_operations",
        "admission_operation_commits",
        "authority_global_commits",
        "admission_operation_commit_meta",
        "authority_global_commit_meta",
    ];
    for version in [18, 19, 20, 23, 24, 25] {
        let fixture = fixture();
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            &format!("versioned-history-{version}"),
            &format!("versioned-capability-{version}"),
        );
        fixture.store.begin(&operation, &fixture.fence, now_ms())?;
        let _lease = claim(&fixture, &operation, "versioned-recovery-owner", now_ms());
        let (before, uuid, anchored_generation) = {
            let connection = fixture.store.connection()?;
            let before = tables
                .iter()
                .map(|table| retained_versioned_rows(&connection, table))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            assert!(before.iter().all(|rows| !rows.is_empty()));
            (
                before,
                fixture.fence.store_uuid.clone(),
                fixture.authority.anchor_generation()?,
            )
        };
        let Fixture {
            _temp,
            database,
            lock_root,
            store,
            authority,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let mut connection = Connection::open(&database)?;
        shape_versioned_predecessor(&mut connection, version)?;
        for (table, expected) in tables.iter().zip(&before) {
            assert_eq!(
                &retained_versioned_rows(&connection, table)?,
                expected,
                "v{version} fixture {table}"
            );
        }
        drop(connection);
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let connection = Connection::open(&database)?;
        for (table, expected) in tables.iter().zip(&before) {
            assert_eq!(
                &retained_versioned_rows(&connection, table)?,
                expected,
                "v{version} public upgrade {table}"
            );
        }
        assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
        assert!(!connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get::<_, bool>(0)
        )?);
        drop(connection);
        let reopened = crate::test_authority::open_serving(&database, &lock_root)?;
        assert_eq!(reopened.mutation_fence().store_uuid, uuid);
        assert!(reopened.anchor_generation()? >= anchored_generation);
        assert_eq!(
            reopened
                .admission_operation_store()
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation)
        );
        drop(reopened);
        drop(_temp);
    }
    Ok(())
}
