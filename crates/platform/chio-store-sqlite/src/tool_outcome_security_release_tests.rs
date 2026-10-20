use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn assert_refusal_without_writes(
    connection: &mut Connection,
    allow_empty: bool,
    expected: ToolOutcomeStoreError,
) -> TestResult {
    let catalog = tool_outcome_schema_catalog(connection)?;
    let application_id: i32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let schema_version: i32 =
        connection.pragma_query_value(None, "schema_version", |row| row.get(0))?;
    let changes = connection.total_changes();
    assert_eq!(
        preflight_tool_outcome_schema(connection, allow_empty).and_then(|()| {
            crate::test_schema::apply(
                connection,
                &[TOOL_OUTCOME_SCHEMA_KEY],
                initialize_tool_outcome_schema,
                |error| invariant(error.to_string()),
            )
        }),
        Err(expected)
    );
    assert_eq!(tool_outcome_schema_catalog(connection)?, catalog);
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        application_id
    );
    assert_eq!(
        connection.pragma_query_value(None, "schema_version", |row| row.get::<_, i32>(0))?,
        schema_version
    );
    assert_eq!(connection.total_changes(), changes);
    Ok(())
}

#[test]
fn tool_outcome_store_refuses_noncurrent_stamp_without_writes() -> TestResult {
    for found in [4, 3, 2, 0, -1, i32::MAX] {
        let mut connection = Connection::open_in_memory()?;
        crate::test_schema::apply(
            &mut connection,
            &[TOOL_OUTCOME_SCHEMA_KEY],
            initialize_tool_outcome_schema,
            |error| invariant(error.to_string()),
        )?;
        crate::test_schema::write_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, found)?;
        let expected = ToolOutcomeStoreError::NoncurrentSchema { found, current: 1 };
        assert_eq!(
            expected.to_string(),
            format!(
                "tool outcome schema version {found} is not the current schema version 1; refusing to open"
            )
        );
        assert_refusal_without_writes(&mut connection, true, expected)?;
        assert_eq!(
            connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
                [],
                |row| row.get::<_, i32>(0),
            )?,
            found
        );
    }
    Ok(())
}

#[test]
fn tool_outcome_store_creates_v1_and_reopens_without_writes() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    crate::test_schema::apply(
        &mut connection,
        &[TOOL_OUTCOME_SCHEMA_KEY],
        initialize_tool_outcome_schema,
        |error| invariant(error.to_string()),
    )?;
    assert_eq!(
        connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            [],
            |row| row.get::<_, i32>(0),
        )?,
        1
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM tool_outcome_security_releases",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    let catalog = tool_outcome_schema_catalog(&connection)?;
    let changes = connection.total_changes();
    let schema_version: i32 =
        connection.pragma_query_value(None, "schema_version", |row| row.get(0))?;
    crate::test_schema::apply(
        &mut connection,
        &[TOOL_OUTCOME_SCHEMA_KEY],
        initialize_tool_outcome_schema,
        |error| invariant(error.to_string()),
    )?;
    assert_eq!(tool_outcome_schema_catalog(&connection)?, catalog);
    assert_eq!(connection.total_changes(), changes);
    assert_eq!(
        connection.pragma_query_value(None, "schema_version", |row| row.get::<_, i32>(0))?,
        schema_version
    );
    Ok(())
}

#[test]
fn tool_outcome_store_refuses_v1_without_release_and_retention_contracts() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    let schema = TOOL_OUTCOME_SCHEMA
        .split("CREATE INDEX IF NOT EXISTS tool_outcomes_raw_digest_owners")
        .next()
        .ok_or("outcome table definitions are missing")?
        .replace(
            "  OR (OLD.canonical_bytes IS NULL AND NEW.canonical_bytes IS NULL)\n  OR (OLD.canonical_bytes IS NOT NULL AND NEW.canonical_bytes IS NOT NULL)",
            "  OR OLD.canonical_bytes IS NULL\n  OR NEW.canonical_bytes IS NOT NULL",
        );
    connection.execute_batch(&schema)?;
    connection.execute_batch(
        r#"CREATE TRIGGER IF NOT EXISTS tool_outcome_blobs_compaction_requires_terminal
BEFORE UPDATE OF canonical_bytes ON tool_outcome_blobs
WHEN NEW.canonical_bytes IS NULL
  AND (
      NOT EXISTS (
          SELECT 1 FROM tool_outcomes
          WHERE raw_output_digest = OLD.digest
      )
      OR EXISTS (
          SELECT 1 FROM tool_outcomes o
          JOIN admission_operations a ON a.operation_id = o.operation_id
          WHERE o.raw_output_digest = OLD.digest
            AND a.terminal = 0
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob is retained while an owning operation is live');
END;"#,
    )?;
    connection.pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)?;
    crate::test_schema::write_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, 1)?;
    assert_refusal_without_writes(
        &mut connection,
        true,
        invariant("tool outcome schema differs from the canonical definition"),
    )
}

#[test]
fn tool_outcome_store_refuses_damaged_v1_without_repair() -> TestResult {
    for damage in [
        "DROP TABLE tool_outcome_security_releases",
        "DROP TABLE post_return_evaluations",
        "DROP TRIGGER tool_outcome_blobs_immutable",
        "DROP INDEX tool_outcomes_raw_digest_owners",
        "DROP TRIGGER tool_outcome_security_releases_no_delete; CREATE TRIGGER tool_outcome_security_releases_no_delete BEFORE DELETE ON tool_outcome_security_releases BEGIN SELECT 1; END",
        "CREATE TABLE TOOL_OUTCOME_SHADOW (payload BLOB)",
        "CREATE TRIGGER unrelated_outcome_guard AFTER INSERT ON tool_outcome_blobs BEGIN SELECT 1; END",
    ] {
        let mut connection = Connection::open_in_memory()?;
        crate::test_schema::apply(&mut connection, &[TOOL_OUTCOME_SCHEMA_KEY], initialize_tool_outcome_schema, |error| invariant(error.to_string()))?;
        connection.execute_batch(damage)?;
        assert_refusal_without_writes(
            &mut connection, true,
            invariant("tool outcome schema differs from the canonical definition"),
        )?;
    }
    Ok(())
}

#[test]
fn tool_outcome_store_refuses_missing_stamp_with_owned_schema() -> TestResult {
    for damage in [
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
        "DROP TABLE chio_store_schema_versions",
    ] {
        let mut connection = Connection::open_in_memory()?;
        crate::test_schema::apply(
            &mut connection,
            &[TOOL_OUTCOME_SCHEMA_KEY],
            initialize_tool_outcome_schema,
            |error| invariant(error.to_string()),
        )?;
        connection.execute_batch(damage)?;
        assert_refusal_without_writes(
            &mut connection,
            true,
            invariant("unstamped tool outcome schema cannot be adopted"),
        )?;
    }
    Ok(())
}

#[test]
fn tool_outcome_store_refuses_unstamped_namespace_beside_admission_store() -> TestResult {
    for owned_schema in [
        "CREATE TABLE TOOL_OUTCOME_BLOBS (payload BLOB)",
        "CREATE VIEW POST_RETURN_EVALUATIONS AS SELECT 1",
        "CREATE TRIGGER outcome_guard AFTER INSERT ON TOOL_OUTCOME_BLOBS BEGIN SELECT 1; END",
    ] {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)?;
        connection.execute_batch("CREATE TABLE admission_operations (operation_id TEXT)")?;
        if owned_schema.starts_with("CREATE TRIGGER") {
            connection.execute_batch("CREATE TABLE TOOL_OUTCOME_BLOBS (payload BLOB)")?;
        }
        connection.execute_batch(owned_schema)?;
        assert_refusal_without_writes(
            &mut connection,
            true,
            invariant("unstamped tool outcome schema cannot be adopted"),
        )?;
    }
    Ok(())
}

#[test]
fn tool_outcome_store_initializes_beside_admission_store() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    crate::test_schema::apply(
        &mut connection,
        &["admission_operation", TOOL_OUTCOME_SCHEMA_KEY],
        |schema| {
            if schema.is_fresh() {
                schema
                    .connection()
                    .execute_batch("CREATE TABLE admission_operations (operation_id TEXT)")
                    .map_err(|error| invariant(error.to_string()))?;
                schema
                    .stamp("admission_operation")
                    .map_err(|error| invariant(error.to_string()))?;
            }
            initialize_tool_outcome_schema(schema)
        },
        |error| invariant(error.to_string()),
    )?;
    crate::test_schema::apply(
        &mut connection,
        &["admission_operation", TOOL_OUTCOME_SCHEMA_KEY],
        |schema| {
            if schema.is_fresh() {
                schema
                    .connection()
                    .execute_batch("CREATE TABLE admission_operations (operation_id TEXT)")
                    .map_err(|error| invariant(error.to_string()))?;
                schema
                    .stamp("admission_operation")
                    .map_err(|error| invariant(error.to_string()))?;
            }
            initialize_tool_outcome_schema(schema)
        },
        |error| invariant(error.to_string()),
    )?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM chio_store_schema_versions WHERE version = 1",
            [],
            |row| row.get::<_, i32>(0),
        )?,
        2
    );
    Ok(())
}

#[test]
fn tool_outcome_store_refuses_damaged_application_identity() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    crate::test_schema::apply(
        &mut connection,
        &[TOOL_OUTCOME_SCHEMA_KEY],
        initialize_tool_outcome_schema,
        |error| invariant(error.to_string()),
    )?;
    connection.pragma_update(None, "application_id", 0)?;
    assert_refusal_without_writes(
        &mut connection,
        true,
        invariant("unstamped security release source cannot be adopted"),
    )?;
    connection.execute_batch("DROP TABLE tool_outcome_security_releases")?;
    assert_refusal_without_writes(
        &mut connection,
        true,
        invariant("versioned outcome source has a damaged application identity"),
    )
}

#[test]
fn tool_outcome_store_refuses_unstamped_owned_tables() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch("CREATE TABLE tool_outcomes (operation_id TEXT)")?;
    assert_refusal_without_writes(
        &mut connection,
        true,
        invariant("unstamped tool outcome schema cannot be adopted"),
    )
}

#[test]
fn tool_outcome_store_refuses_noncanonical_version_namespace() -> TestResult {
    for app_id in [0, crate::CHIO_SQLITE_APPLICATION_ID] {
        for metadata in [
            "CREATE TABLE CHIO_STORE_SCHEMA_VERSIONS (store_key TEXT PRIMARY KEY, version INTEGER NOT NULL)",
            "CREATE VIEW chio_store_schema_versions AS SELECT 'tool_outcome' AS store_key, 1 AS version",
        ] {
            let mut connection = Connection::open_in_memory()?;
            connection.execute_batch("CREATE TABLE tool_outcomes (operation_id TEXT)")?;
            connection.execute_batch(metadata)?;
            connection.pragma_update(None, "application_id", app_id)?;
            assert_refusal_without_writes(
                &mut connection, true,
                invariant("outcome schema-version namespace is not canonical"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn tool_outcome_store_refuses_foreign_identity() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.pragma_update(None, "application_id", 0x1234_5678)?;
    assert_refusal_without_writes(
        &mut connection,
        true,
        invariant(
            crate::SchemaVersionError::ForeignDatabase {
                found: 0x1234_5678,
                expected: crate::CHIO_SQLITE_APPLICATION_ID,
            }
            .to_string(),
        ),
    )
}

#[test]
fn tool_outcome_preflight_leaves_a_fresh_database_unstamped() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.pragma_update(None, "query_only", true)?;
    let before_catalog = tool_outcome_schema_catalog(&connection)?;
    let before_changes = connection.total_changes();
    preflight_tool_outcome_schema(&connection, true)?;
    assert_eq!(tool_outcome_schema_catalog(&connection)?, before_catalog);
    assert_eq!(connection.total_changes(), before_changes);
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    assert_eq!(
        connection.pragma_query_value(None, "schema_version", |row| row.get::<_, i32>(0))?,
        0
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row
            .get::<_, i64>(0),)?,
        0
    );
    Ok(())
}

#[test]
fn outcome_view_without_application_identity_is_refused_before_writes() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch("CREATE VIEW TOOL_OUTCOMES AS SELECT 1")?;
    assert_refusal_without_writes(
        &mut connection,
        true,
        invariant("unstamped tool outcome schema cannot be adopted"),
    )
}

#[test]
fn provisioned_outcome_initializer_refuses_namespace_deleted_after_preflight() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    crate::test_schema::apply(
        &mut connection,
        &[TOOL_OUTCOME_SCHEMA_KEY],
        initialize_tool_outcome_schema,
        |error| invariant(error.to_string()),
    )?;
    preflight_tool_outcome_schema(&connection, false)?;
    connection.execute_batch(
        "DROP TABLE tool_outcome_security_releases;
         DROP TABLE post_return_evaluations;
         DROP TABLE tool_outcomes;
         DROP TABLE tool_outcome_blobs;
         DELETE FROM chio_store_schema_versions WHERE store_key = 'tool_outcome';",
    )?;
    assert_refusal_without_writes(
        &mut connection,
        false,
        ToolOutcomeStoreError::Invariant("provisioned tool outcome schema is missing".into()),
    )?;
    Ok(())
}
