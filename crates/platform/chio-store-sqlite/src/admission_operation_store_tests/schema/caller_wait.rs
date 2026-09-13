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
    assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i64>(0))?, 34);
    let bad_foreign_key: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |row| row.get(0),
    )?;
    assert!(!bad_foreign_key);
    drop(connection);
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}
