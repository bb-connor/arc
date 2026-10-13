//! The v37 to v38 recovery runtime upgrade preserves operation and commit bytes.
use super::*;

/// Disposable predecessor construction must never erase recovery custody or
/// an authenticated global reference. Production migrations do not use this.
pub(super) fn remove_empty_recovery_tables(connection: &Connection) -> rusqlite::Result<()> {
    for table in [
        "admission_operation_recovery_events",
        "admission_operation_recovery_records",
    ] {
        assert_eq!(
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })?,
            0,
            "predecessor fixture cannot discard recovery history"
        );
    }
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'recovery'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0,
        "predecessor fixture cannot discard global recovery references"
    );
    connection.execute_batch(
        "DROP TABLE admission_operation_recovery_events;
         DROP TABLE admission_operation_recovery_records;",
    )
}

fn rows(connection: &Connection, table: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    assert!(matches!(
        table,
        "admission_operations" | "admission_operation_commits" | "authority_global_commits"
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

fn populated_v37_fixture() -> AnchoredTestResult<(Fixture, AdmissionOperationV1)> {
    let f = fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "predecessor-operation",
        "predecessor-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
    let _lease = claim(&f, &operation, "predecessor-owner", now_ms());
    Ok((f, operation))
}

fn stamp_v37(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 37 WHERE store_key = 'admission_operation'",
        [],
    )?;
    Ok(())
}

#[test]
fn recovery_runtime_upgrade_from_v37_preserves_operations_and_global_chain() -> AnchoredTestResult
{
    let (f, operation) = populated_v37_fixture()?;
    let tables = [
        "admission_operations",
        "admission_operation_commits",
        "authority_global_commits",
    ];
    let before = {
        let db = f.store.connection()?;
        tables
            .iter()
            .map(|table| rows(&db, table))
            .collect::<AnchoredTestResult<Vec<_>>>()?
    };
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        ..
    } = f;
    drop(store);
    drop(authority);
    {
        let db = Connection::open(&database)?;
        remove_empty_recovery_tables(&db)?;
        stamp_v37(&db)?;
    }
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let db = Connection::open(&database)?;
    for (table, expected) in tables.iter().zip(&before) {
        assert_eq!(expected, &rows(&db, table)?, "rewrote predecessor: {table}");
    }
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
            [],
            |row| row.get::<_, i32>(0),
        )?,
        crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    drop(db);
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

#[test]
fn recovery_runtime_upgrade_refuses_a_v37_stamp_over_runtime_tables() -> AnchoredTestResult {
    let (f, _operation) = populated_v37_fixture()?;
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        ..
    } = f;
    drop(store);
    drop(authority);
    stamp_v37(&Connection::open(&database)?)?;
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    Ok(())
}
