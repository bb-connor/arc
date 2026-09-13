use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn v33_catalog_upgrade_is_exact_and_preserves_parent_names() -> TestResult {
    let mut connection = expected_admission_operation_schema(33)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    migration_v17::preserving_parent_names(&mut connection, |connection| {
        let tx = connection.transaction().map_err(sqlite_error)?;
        migrate(&tx, 33)?;
        verify_admission_operation_schema(&tx, 34)?;
        // An idempotent repeat must not rebuild the current parent again.
        migrate(&tx, 34)?;
        verify_admission_operation_schema(&tx, 34)?;
        tx.commit().map_err(sqlite_error)
    })?;
    assert!(connection.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?);
    assert!(
        !connection.pragma_query_value(None, "legacy_alter_table", |row| row.get::<_, bool>(0))?
    );
    let redirected: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE sql LIKE '%admission_operations_v33%')",
        [],
        |row| row.get(0),
    )?;
    assert!(!redirected);
    Ok(())
}

#[test]
fn v33_missing_barrier_and_future_catalog_are_not_adopted() -> TestResult {
    for sql in [
        "DROP TRIGGER admission_operations_terminal_immutable",
        "DROP TRIGGER admission_operation_caller_contexts_immutable",
        "DROP INDEX admission_operations_request_id",
        "CREATE TABLE admission_operation_unqualified(value INTEGER)",
    ] {
        let connection = expected_admission_operation_schema(33)?;
        connection.execute_batch(sql)?;
        let before = admission_operation_schema_catalog(&connection)?;
        assert!(verify_pre_migration_schema(&connection, 33).is_err());
        assert_eq!(before, admission_operation_schema_catalog(&connection)?);
    }
    let future = expected_admission_operation_schema(34)?;
    assert!(verify_pre_migration_schema(&future, 33).is_err());
    Ok(())
}
