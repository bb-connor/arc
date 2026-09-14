use super::*;

fn predecessor() -> AnchoredTestResult<(Fixture, Connection)> {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "v34-preserved-request",
        "v34-preserved-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    let connection = Connection::open(&fixture.database)?;
    connection.execute_batch(
        "DROP TABLE IF EXISTS unknown_payment_release_records;
         UPDATE chio_store_schema_versions SET version = 34
         WHERE store_key = 'admission_operation';",
    )?;
    Ok((fixture, connection))
}

fn snapshot(connection: &Connection, table: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    // Table names below are fixed test constants.
    let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let count = statement.column_count();
    let rows = statement
        .query_map([], |row| (0..count).map(|i| row.get(i)).collect())?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn history(connection: &Connection) -> AnchoredTestResult<Vec<Vec<Vec<Value>>>> {
    [
        "admission_operations",
        "admission_operation_commits",
        "admission_operation_commit_meta",
        "authority_global_commits",
    ]
    .into_iter()
    .map(|table| snapshot(connection, table))
    .collect()
}

#[test]
fn v35_upgrades_exact_v34_without_rewriting_operation_or_anchored_history() -> AnchoredTestResult {
    let (_fixture, mut connection) = predecessor()?;
    let before = history(&connection)?;
    initialize_admission_operation_schema(&mut connection)?;
    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 35);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM unknown_payment_release_records",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert_eq!(history(&connection)?, before);
    initialize_admission_operation_schema(&mut connection)?;
    assert_eq!(history(&connection)?, before);
    Ok(())
}

#[test]
fn v35_rejects_weakened_or_future_v34_catalog_without_mutation() -> AnchoredTestResult {
    for sql in [
        "DROP TRIGGER admission_operations_terminal_immutable",
        "DROP TRIGGER admission_operation_caller_contexts_immutable",
        "DROP INDEX admission_operations_request_id",
        "CREATE TABLE unknown_payment_release_unqualified(value INTEGER)",
    ] {
        let (_fixture, mut connection) = predecessor()?;
        connection.execute_batch(sql)?;
        let catalog = snapshot(&connection, "sqlite_schema")?;
        let before = history(&connection)?;
        let versions = snapshot(&connection, "chio_store_schema_versions")?;
        assert!(initialize_admission_operation_schema(&mut connection).is_err());
        assert_eq!(snapshot(&connection, "sqlite_schema")?, catalog);
        assert_eq!(history(&connection)?, before);
        assert_eq!(
            snapshot(&connection, "chio_store_schema_versions")?,
            versions
        );
    }
    Ok(())
}

#[test]
fn v35_rejects_research_v10_release_namespace_without_mutation() -> AnchoredTestResult {
    let (_fixture, mut connection) = predecessor()?;
    connection.execute_batch(include_str!("../admission_operation_unknown_release.sql"))?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 10 WHERE store_key = 'admission_operation'",
        [],
    )?;
    let catalog = snapshot(&connection, "sqlite_schema")?;
    let before = history(&connection)?;
    assert!(initialize_admission_operation_schema(&mut connection).is_err());
    assert_eq!(snapshot(&connection, "sqlite_schema")?, catalog);
    assert_eq!(history(&connection)?, before);
    Ok(())
}

#[test]
fn v35_reopen_rejects_missing_immutable_release_barrier() -> AnchoredTestResult {
    let fixture = fixture();
    let mut connection = Connection::open(&fixture.database)?;
    connection.execute_batch("DROP TRIGGER unknown_payment_release_records_immutable")?;
    let catalog = snapshot(&connection, "sqlite_schema")?;
    assert!(initialize_admission_operation_schema(&mut connection).is_err());
    assert_eq!(snapshot(&connection, "sqlite_schema")?, catalog);
    Ok(())
}
