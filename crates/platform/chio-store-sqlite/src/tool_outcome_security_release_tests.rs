use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn current() -> TestResult<Connection> {
    let mut connection = Connection::open_in_memory()?;
    initialize_tool_outcome_schema(&mut connection)?;
    Ok(connection)
}

fn stamped_version(connection: &Connection, table: &str) -> TestResult<i32> {
    Ok(connection.query_row(
        &format!("SELECT version FROM {table} WHERE store_key = 'tool_outcome'"),
        [],
        |row| row.get(0),
    )?)
}

fn application_id(connection: &Connection) -> TestResult<i32> {
    Ok(connection.pragma_query_value(None, "application_id", |row| row.get(0))?)
}

fn refusal(connection: &mut Connection) -> TestResult<String> {
    match initialize_tool_outcome_schema(connection) {
        Ok(()) => Err("tool outcome schema must be refused".into()),
        Err(error) => Ok(error.to_string()),
    }
}

#[test]
fn fresh_schema_is_stamped_v1_without_release_acknowledgements() -> TestResult {
    let mut connection = current()?;
    assert_eq!(
        stamped_version(&connection, "chio_store_schema_versions")?,
        1
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
fn every_other_stamped_version_is_refused_without_rewriting() -> TestResult {
    for version in [0, 2, 3, 4, 5] {
        let mut connection = current()?;
        connection.execute(
            "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = 'tool_outcome'",
            [version],
        )?;
        let before = tool_outcome_schema_catalog(&connection)?;
        assert_eq!(
            refusal(&mut connection)?,
            format!(
                "tool outcome invariant failed: database schema version {version} is not the \
                 current schema version 1; refusing to open"
            )
        );
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
        assert_eq!(
            stamped_version(&connection, "chio_store_schema_versions")?,
            version
        );
    }
    Ok(())
}

#[test]
fn provisioned_storage_without_a_stamp_is_refused() -> TestResult {
    for sql in [
        TOOL_OUTCOME_SCHEMA,
        "CREATE TABLE tool_outcome_security_releases(fake TEXT)",
        "CREATE VIEW tool_outcome_security_releases AS SELECT 1",
        "CREATE TABLE post_return_evaluations(fake TEXT)",
    ] {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)?;
        connection.execute_batch("CREATE TABLE admission_operations(fake TEXT)")?;
        connection.execute_batch(sql)?;
        let before = tool_outcome_schema_catalog(&connection)?;
        assert_eq!(
            refusal(&mut connection)?,
            "tool outcome invariant failed: tool outcome storage is provisioned without a \
             schema stamp"
        );
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
        assert!(!connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_store_schema_versions')",
            [],
            |row| row.get::<_, bool>(0)
        )?);
    }
    Ok(())
}

#[test]
fn a_populated_store_with_a_cleared_identity_is_refused() -> TestResult {
    let mut connection = current()?;
    connection.execute_batch("PRAGMA application_id = 0")?;
    assert_eq!(
        refusal(&mut connection)?,
        "tool outcome invariant failed: database application_id 0x0 is not a Chio store \
         (expected 0x4348494f)"
    );
    assert_eq!(application_id(&connection)?, 0);
    assert_eq!(
        stamped_version(&connection, "chio_store_schema_versions")?,
        1
    );
    Ok(())
}

#[test]
fn an_unstamped_populated_file_is_refused_without_adoption() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
    let before = tool_outcome_schema_catalog(&connection)?;
    assert_eq!(
        refusal(&mut connection)?,
        "tool outcome invariant failed: database application_id 0x0 is not a Chio store \
         (expected 0x4348494f)"
    );
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    assert_eq!(application_id(&connection)?, 0);
    Ok(())
}

#[test]
fn alternate_case_version_metadata_cannot_hide_a_stamped_revision() -> TestResult {
    for cleared in [false, true] {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
        connection.execute_batch(
            "CREATE TABLE CHIO_STORE_SCHEMA_VERSIONS (store_key TEXT PRIMARY KEY, version INTEGER NOT NULL)",
        )?;
        connection.execute(
            "INSERT INTO CHIO_STORE_SCHEMA_VERSIONS VALUES (?1, 4)",
            [TOOL_OUTCOME_SCHEMA_KEY],
        )?;
        let app_id = if cleared {
            0
        } else {
            crate::CHIO_SQLITE_APPLICATION_ID
        };
        connection.pragma_update(None, "application_id", app_id)?;
        let before = tool_outcome_schema_catalog(&connection)?;
        let expected = if cleared {
            "tool outcome invariant failed: database application_id 0x0 is not a Chio store \
             (expected 0x4348494f)"
        } else {
            "tool outcome invariant failed: tool outcome storage is provisioned without a \
             schema stamp"
        };
        assert_eq!(refusal(&mut connection)?, expected);
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
        assert_eq!(application_id(&connection)?, app_id);
        assert_eq!(
            stamped_version(&connection, "CHIO_STORE_SCHEMA_VERSIONS")?,
            4
        );
    }
    Ok(())
}

#[test]
fn a_current_store_missing_an_immutable_guard_is_refused_without_repair() -> TestResult {
    let mut connection = current()?;
    connection.execute_batch("DROP TRIGGER tool_outcome_blobs_immutable")?;
    let before = tool_outcome_schema_catalog(&connection)?;
    assert_eq!(
        refusal(&mut connection)?,
        "tool outcome invariant failed: tool outcome schema differs from the canonical \
         definition"
    );
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    Ok(())
}
