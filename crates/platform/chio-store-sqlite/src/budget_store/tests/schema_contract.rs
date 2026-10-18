use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type DatabaseSnapshot = Vec<(String, Vec<String>)>;

pub(super) fn populated_database() -> TestResult<(tempfile::TempDir, std::path::PathBuf)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.db");
    drop(SqliteBudgetStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE budget_replication_meta SET next_seq = 41 WHERE singleton = 1",
        [],
    )?;
    Ok((directory, path))
}

pub(super) fn snapshot(connection: &Connection) -> TestResult<DatabaseSnapshot> {
    let mut statements = vec![(
        "sqlite_schema".to_owned(),
        "SELECT type, name, tbl_name, sql FROM sqlite_schema".to_owned(),
    )];
    let mut tables = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    for table in tables.query_map([], |row| row.get::<_, String>(0))? {
        let table = table?;
        let query = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
        statements.push((table, query));
    }
    let mut result = vec![
        (
            "application_id".into(),
            vec![connection
                .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))?
                .to_string()],
        ),
        (
            "user_version".into(),
            vec![connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?
                .to_string()],
        ),
        (
            "journal_mode".into(),
            vec![connection
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?],
        ),
    ];
    for (name, sql) in statements {
        let mut statement = connection.prepare(&sql)?;
        let columns = statement.column_count();
        let mut rows = statement
            .query_map([], |row| {
                let values = (0..columns)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("{values:?}"))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.sort();
        result.push((name, rows));
    }
    Ok(result)
}

pub(super) fn assert_refused_without_mutation(
    path: &std::path::Path,
    expected: &str,
) -> TestResult {
    let connection = Connection::open(path)?;
    let before = snapshot(&connection)?;
    let error = match SqliteBudgetStore::open(path) {
        Ok(_) => panic!("budget store accepted an incompatible persisted schema"),
        Err(error) => error,
    };
    match error {
        BudgetStoreError::Invariant(message) => assert_eq!(message, expected),
        other => panic!("unexpected budget schema refusal: {other:?}"),
    }
    assert_eq!(snapshot(&connection)?, before);
    Ok(())
}

#[test]
fn budget_schema_refuses_missing_quota_table_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP TABLE budget_event_quota_members")?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema does not match the current v1 shape")
}

#[test]
fn budget_schema_refuses_unstamped_current_catalog_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'budget'",
        [],
    )?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema does not match the current v1 shape")
}

#[test]
fn budget_schema_refuses_additional_trigger_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER unrelated_name BEFORE UPDATE ON budget_replication_meta
         BEGIN SELECT RAISE(ABORT, 'untrusted trigger'); END;",
    )?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema does not match the current v1 shape")
}

#[test]
fn budget_schema_refuses_missing_sequence_state_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute("DELETE FROM budget_replication_meta", [])?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget replication state is invalid")
}
