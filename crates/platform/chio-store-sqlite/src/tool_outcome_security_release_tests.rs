use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn predecessor() -> TestResult<Connection> {
    let connection = Connection::open_in_memory()?;
    crate::check_schema_version(
        &connection,
        TOOL_OUTCOME_SCHEMA_KEY,
        2,
        TOOL_OUTCOME_SCHEMA_ANCHORS,
    )?;
    connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
    crate::stamp_schema_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, 2)?;
    Ok(connection)
}

#[test]
fn exact_v2_migration_creates_no_release_acknowledgements() -> TestResult {
    let mut connection = predecessor()?;
    initialize_tool_outcome_schema(&mut connection)?;
    assert_eq!(
        connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        3
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
fn v2_migration_refuses_an_unqualified_release_namespace() -> TestResult {
    for sql in [
        "CREATE TABLE tool_outcome_security_releases(fake TEXT)",
        "CREATE VIEW tool_outcome_security_releases AS SELECT 1",
    ] {
        let mut connection = predecessor()?;
        connection.execute_batch(sql)?;
        let before = tool_outcome_schema_catalog(&connection)?;
        assert!(initialize_tool_outcome_schema(&mut connection).is_err());
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
        assert_eq!(
            connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
    }
    Ok(())
}

#[test]
fn v2_migration_refuses_missing_immutable_guards_without_repair() -> TestResult {
    let mut connection = predecessor()?;
    connection.execute_batch("DROP TRIGGER tool_outcome_blobs_immutable")?;
    let before = tool_outcome_schema_catalog(&connection)?;
    assert!(initialize_tool_outcome_schema(&mut connection).is_err());
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    assert_eq!(
        connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        2
    );
    Ok(())
}

#[test]
fn exact_v1_and_unversioned_predecessors_migrate_without_invented_releases() -> TestResult {
    for version in [0, 1] {
        let mut connection = Connection::open_in_memory()?;
        crate::check_schema_version(
            &connection,
            TOOL_OUTCOME_SCHEMA_KEY,
            2,
            TOOL_OUTCOME_SCHEMA_ANCHORS,
        )?;
        connection.execute_batch(&predecessor_schema(1))?;
        if version != 0 {
            crate::stamp_schema_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, version)?;
        }
        initialize_tool_outcome_schema(&mut connection)?;
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM tool_outcome_security_releases",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    Ok(())
}

#[test]
fn a_damaged_release_source_identity_is_not_restamped_on_failure() -> TestResult {
    let mut connection = predecessor()?;
    initialize_tool_outcome_schema(&mut connection)?;
    connection.execute_batch("PRAGMA application_id = 0")?;
    assert!(initialize_tool_outcome_schema(&mut connection).is_err());
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    Ok(())
}

#[test]
fn rejected_unstamped_predecessor_rolls_back_identity_and_schema() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(&predecessor_schema(1))?;
    connection.execute_batch("DROP TRIGGER tool_outcome_blobs_immutable")?;
    let before = tool_outcome_schema_catalog(&connection)?;
    assert!(initialize_tool_outcome_schema(&mut connection).is_err());
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    assert!(!connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_store_schema_versions')",
        [],
        |row| row.get::<_, bool>(0)
    )?);
    Ok(())
}

#[test]
fn version_metadata_with_cleared_identity_cannot_be_adopted_as_legacy() -> TestResult {
    for version in [1, 2, 4] {
        let mut connection = predecessor()?;
        crate::stamp_schema_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, version)?;
        connection.execute_batch("PRAGMA application_id = 0")?;
        assert!(initialize_tool_outcome_schema(&mut connection).is_err());
        assert_eq!(
            connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
                [],
                |row| row.get::<_, i32>(0)
            )?,
            version
        );
    }
    Ok(())
}

#[test]
fn alternate_case_version_metadata_cannot_hide_a_future_source_revision() -> TestResult {
    for cleared in [false, true] {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
        connection.execute_batch("CREATE TABLE CHIO_STORE_SCHEMA_VERSIONS (store_key TEXT PRIMARY KEY, version INTEGER NOT NULL)")?;
        connection.execute(
            "INSERT INTO CHIO_STORE_SCHEMA_VERSIONS VALUES (?1, 4)",
            [TOOL_OUTCOME_SCHEMA_KEY],
        )?;
        connection.pragma_update(
            None,
            "application_id",
            if cleared {
                0
            } else {
                crate::CHIO_SQLITE_APPLICATION_ID
            },
        )?;
        let before = tool_outcome_schema_catalog(&connection)?;
        let app_id =
            connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?;
        let error = match initialize_tool_outcome_schema(&mut connection) {
            Ok(()) => return Err("noncanonical metadata must be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("schema-version namespace"));
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
        assert_eq!(
            connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
            app_id
        );
        assert_eq!(
            connection.query_row(
                "SELECT version FROM CHIO_STORE_SCHEMA_VERSIONS WHERE store_key = 'tool_outcome'",
                [],
                |row| row.get::<_, i32>(0)
            )?,
            4
        );
    }
    Ok(())
}

#[test]
fn exact_unstamped_legacy_source_is_stamped_only_after_successful_migration() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(&predecessor_schema(1))?;
    initialize_tool_outcome_schema(&mut connection)?;
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        crate::CHIO_SQLITE_APPLICATION_ID
    );
    assert_eq!(
        connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            [],
            |row| row.get::<_, i32>(0)
        )?,
        3
    );
    Ok(())
}
