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
fn budget_schema_refuses_stamp_twelve_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    crate::test_schema::write_version(&connection, "budget", 12)?;
    drop(connection);
    assert_stale_without_mutation(&path, 12)
}

#[test]
fn budget_schema_refuses_additional_hold_column_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "ALTER TABLE budget_authorization_holds ADD COLUMN unexpected_reservation INTEGER",
    )?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema does not match the current v1 shape")
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
fn budget_schema_refuses_incomplete_stamp_one_without_mutation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.db");
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TABLE capability_grant_budgets (
             capability_id TEXT NOT NULL,
             grant_index INTEGER NOT NULL,
             invocation_count INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             seq INTEGER NOT NULL DEFAULT 0,
             total_cost_exposed INTEGER NOT NULL DEFAULT 0,
             total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (capability_id, grant_index)
         );",
    )?;
    connection.pragma_update(
        None,
        "application_id",
        crate::schema_version::CHIO_SQLITE_APPLICATION_ID,
    )?;
    crate::test_schema::write_version(&connection, "budget", 1)?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema does not match the current v1 shape")
}

#[test]
fn budget_schema_creates_and_reopens_version_one() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.db");
    drop(SqliteBudgetStore::open(&path)?);
    let reopened = SqliteBudgetStore::open(&path)?;
    assert_eq!(reopened.count_open_holds()?, 0);
    let connection = Connection::open(&path)?;
    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'budget'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 1);
    Ok(())
}

#[test]
fn budget_schema_refuses_missing_current_objects_without_mutation() -> TestResult {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(schema::SCHEMA)?;
    let mut statement = canonical.prepare(
        "SELECT type, name FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (kind, name) in objects {
        if name == "capability_grant_budgets" {
            continue;
        }
        let (_directory, path) = populated_database()?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(&format!("DROP {kind} \"{name}\""))?;
        drop(connection);
        assert_refused_without_mutation(
            &path,
            "budget schema does not match the current v1 shape",
        )?;
    }
    Ok(())
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
    assert_refused_without_mutation(&path, "schema namespace budget is missing")
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
fn budget_schema_refuses_changed_current_constraints_without_mutation() -> TestResult {
    for changed in [
        schema::SCHEMA.replace("anchored_schema_version = 1", "anchored_schema_version = 6"),
        schema::SCHEMA.replace(
            "'payment journal identity is immutable'",
            "'payment  journal identity is immutable'",
        ),
        schema::SCHEMA.replace(
            "REFERENCES budget_authorization_holds(operation_id, hold_id)",
            "REFERENCES budget_authorization_holds(hold_id, operation_id)",
        ),
    ] {
        assert_ne!(changed, schema::SCHEMA);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("budget.db");
        let connection = Connection::open(&path)?;
        connection.execute_batch(&changed)?;
        connection.pragma_update(
            None,
            "application_id",
            crate::schema_version::CHIO_SQLITE_APPLICATION_ID,
        )?;
        crate::test_schema::write_version(&connection, "budget", 1)?;
        drop(connection);
        assert_refused_without_mutation(
            &path,
            "budget schema does not match the current v1 shape",
        )?;
    }
    Ok(())
}

#[test]
fn budget_schema_refuses_unbounded_catalog_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(&format!(
        "CREATE TABLE budget_unbounded(payload TEXT DEFAULT '{}')",
        "x".repeat(262_144),
    ))?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema exceeds its catalog bounds")
}

#[test]
fn budget_schema_refuses_missing_sequence_state_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute("DELETE FROM budget_replication_meta", [])?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget replication state is invalid")
}

#[test]
fn budget_schema_refuses_missing_identity_table_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP TABLE capability_grant_budgets")?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget schema does not match the current v1 shape")
}

#[test]
fn budget_schema_refuses_unsequenced_usage_without_mutation() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "INSERT INTO capability_grant_budgets (capability_id, grant_index, invocation_count, updated_at)
         VALUES ('unsequenced', 0, 1, 1)",
        [],
    )?;
    drop(connection);
    assert_refused_without_mutation(&path, "budget replication state is invalid")
}

#[test]
fn budget_schema_refuses_undeclared_colocated_tables() -> TestResult {
    let (_directory, path) = populated_database()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("CREATE TABLE operator_events (sequence INTEGER PRIMARY KEY); INSERT INTO operator_events VALUES (1);")?;
    assert_refused_without_mutation(
        &path,
        "schema catalog differs from its canonical definition",
    )?;
    let sequence: i64 =
        connection.query_row("SELECT sequence FROM operator_events", [], |row| row.get(0))?;
    assert_eq!(sequence, 1);
    Ok(())
}

pub(super) fn assert_stale_without_mutation(path: &std::path::Path, found: i32) -> TestResult {
    let connection = Connection::open(path)?;
    let before = snapshot(&connection)?;
    let error = match SqliteBudgetStore::open(path) {
        Ok(_) => panic!("budget store accepted a noncurrent schema stamp"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        format!(
            "database schema version {found} is not the current schema version 1; refusing to open",
        )
    );
    match error {
        BudgetStoreError::StaleSchema {
            found: actual,
            current,
        } => assert_eq!((actual, current), (found, 1)),
        other => panic!("unexpected budget schema refusal: {other:?}"),
    }
    assert_eq!(snapshot(&connection)?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn budget_schema_reprovisioning_refuses_noncurrent_stamp_without_mutation() -> TestResult {
    let (_directory, path, lock_root) = provisioned_authority()?;
    let connection = Connection::open(&path)?;
    crate::test_schema::write_version(&connection, "budget", 12)?;
    let before = snapshot(&connection)?;
    let error = crate::SqliteAuthorityStore::provision(&path, &lock_root)
        .expect_err("a noncurrent budget stamp cannot be provisioned");
    assert!(matches!(
        error,
        crate::SqliteServingOwnerError::BudgetSchema(BudgetStoreError::StaleSchema {
            found: 12,
            current: 1
        })
    ));
    assert_eq!(snapshot(&connection)?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn budget_schema_provisioning_refuses_unstamped_colocated_catalog_without_mutation() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    for application_id in [crate::CHIO_SQLITE_APPLICATION_ID, 0] {
        let (directory, path) = populated_database()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let lock_root = directory.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))?;
        let connection = Connection::open(&path)?;
        connection.execute_batch("CREATE TABLE revoked_capabilities(capability_id TEXT PRIMARY KEY); DELETE FROM chio_store_schema_versions WHERE store_key = 'budget';")?;
        connection.pragma_update(None, "application_id", application_id)?;
        let before = snapshot(&connection)?;
        let error = crate::SqliteAuthorityStore::provision(&path, &lock_root)
            .expect_err("unstamped budget catalog cannot be provisioned");
        if application_id == 0 {
            assert!(
                matches!(&error, crate::SqliteServingOwnerError::ToolOutcomeSchema(chio_kernel::tool_outcome::ToolOutcomeStoreError::Invariant(message)) if message == "versioned outcome source has a damaged application identity"),
                "unexpected identity refusal: {error:?}"
            );
        } else {
            assert!(
                matches!(&error, crate::SqliteServingOwnerError::PartialProvision(database) if database == &path.display().to_string()),
                "unexpected budget refusal: {error:?}"
            );
        }
        assert_eq!(snapshot(&connection)?, before);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn budget_schema_serving_refuses_noncurrent_stamp_without_mutation() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("authority.db");
    let lock_root = directory.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))?;
    crate::SqliteAuthorityStore::provision(&path, &lock_root)?;
    let connection = Connection::open(&path)?;
    crate::test_schema::write_version(&connection, "budget", 0)?;
    let before = snapshot(&connection)?;
    let error = match crate::test_authority::open_serving(&path, &lock_root) {
        Ok(_) => panic!("noncurrent budget schema cannot serve"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        crate::SqliteServingOwnerError::BudgetSchema(BudgetStoreError::StaleSchema {
            found: 0,
            current: 1
        })
    ));
    assert_eq!(snapshot(&connection)?, before);
    Ok(())
}

#[cfg(unix)]
fn provisioned_authority() -> TestResult<(tempfile::TempDir, std::path::PathBuf, std::path::PathBuf)>
{
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("authority.db");
    let lock_root = directory.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))?;
    crate::SqliteAuthorityStore::provision(&path, &lock_root)?;
    Ok((directory, path, lock_root))
}

#[cfg(unix)]
#[test]
fn budget_schema_reprovision_refuses_deleted_namespace_without_mutation() -> TestResult {
    let (_directory, path, lock_root) = provisioned_authority()?;
    let connection = Connection::open(&path)?;
    let tables = {
        let mut statement = connection.prepare(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND
             (name GLOB 'budget_*' OR name = 'capability_grant_budgets'
              OR name IN ('payment_journal', 'payment_release_evidence'))",
        )?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        names
    };
    for table in tables {
        connection.execute_batch(&format!("DROP TABLE \"{}\"", table.replace('"', "\"\"")))?;
    }
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'budget'",
        [],
    )?;
    let before = snapshot(&connection)?;
    let error = crate::SqliteAuthorityStore::provision(&path, &lock_root)
        .expect_err("reprovisioning cannot recreate deleted budget custody");
    assert!(matches!(error,
        crate::SqliteServingOwnerError::Schema(crate::SchemaVersionError::MissingSchema { ref store_key }) if store_key == "budget"));
    assert_eq!(snapshot(&connection)?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn budget_schema_serving_refuses_catalog_drift_and_missing_stamp_without_mutation() -> TestResult {
    for (damage, missing_stamp) in [
        ("CREATE TRIGGER budget_injected AFTER INSERT ON budget_authorization_holds BEGIN SELECT 1; END;", false),
        ("DELETE FROM chio_store_schema_versions WHERE store_key = 'budget';", true),
    ] {
        let (_directory, path, lock_root) = provisioned_authority()?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(damage)?;
        let before = snapshot(&connection)?;
        let error = match crate::test_authority::open_serving(&path, &lock_root) {
            Ok(_) => panic!("damaged budget schema cannot serve"),
            Err(error) => error,
        };
        if missing_stamp {
            assert!(matches!(error, crate::SqliteServingOwnerError::Schema(crate::SchemaVersionError::MissingSchema { ref store_key }) if store_key == "budget"));
        } else {
            assert!(matches!(error,
                crate::SqliteServingOwnerError::BudgetSchema(BudgetStoreError::Invariant(ref message))
                if message == "budget schema does not match the current v1 shape"));
        }
        assert_eq!(snapshot(&connection)?, before);
    }
    Ok(())
}
