use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn current() -> TestResult<Connection> {
    let mut connection = Connection::open_in_memory()?;
    initialize_tool_outcome_schema(&mut connection)?;
    Ok(connection)
}

#[test]
fn fresh_schema_is_stamped_current_and_reopens() -> TestResult {
    let mut connection = current()?;
    assert_eq!(
        connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            [],
            |row| row.get::<_, i32>(0)
        )?,
        TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM tool_outcome_security_releases",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    initialize_tool_outcome_schema(&mut connection)?;
    Ok(())
}

#[test]
fn obsolete_schema_is_refused_without_rewriting() -> TestResult {
    let mut connection = current()?;
    crate::stamp_schema_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, 0)?;
    let before = tool_outcome_schema_catalog(&connection)?;
    let error = initialize_tool_outcome_schema(&mut connection)
        .err()
        .ok_or("an obsolete outcome schema opened")?;
    assert!(
        error
            .to_string()
            .contains("is not the current schema version"),
        "{error}"
    );
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    Ok(())
}

#[test]
fn cleared_application_identity_is_refused_without_restamping() -> TestResult {
    let mut connection = current()?;
    connection.execute_batch("PRAGMA application_id = 0")?;
    let error = initialize_tool_outcome_schema(&mut connection)
        .err()
        .ok_or("an unstamped outcome source opened")?;
    assert!(error.to_string().contains("is not a Chio store"), "{error}");
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    Ok(())
}

#[test]
fn unstamped_outcome_schema_is_refused_without_adoption() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
    let before = tool_outcome_schema_catalog(&connection)?;
    let error = initialize_tool_outcome_schema(&mut connection)
        .err()
        .ok_or("an unstamped outcome schema opened")?;
    assert!(error.to_string().contains("is not a Chio store"), "{error}");
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    assert!(!connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_store_schema_versions')",
        [],
        |row| row.get::<_, bool>(0)
    )?);
    Ok(())
}
