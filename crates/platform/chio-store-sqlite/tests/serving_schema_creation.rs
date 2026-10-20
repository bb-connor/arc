#![cfg(target_os = "linux")]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use chio_store_sqlite::{SqliteAuthorityStore, SqliteServingOwnerError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(tempfile::TempDir, std::path::PathBuf, std::path::PathBuf), std::io::Error>
{
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let database = root.path().join("authority.db");
    let locks = root.path().join("locks");
    std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
    Ok((root, database, locks))
}

#[test]
fn fresh_serving_schema_creation_and_reopen_succeed() -> TestResult {
    let (_root, database, locks) = fixture()?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    drop(SqliteAuthorityStore::open_serving(&database, &locks)?);
    drop(SqliteAuthorityStore::open_serving(&database, &locks)?);
    Ok(())
}

#[test]
fn serving_reopen_refuses_missing_namespace_without_repair() -> TestResult {
    let (_root, database, locks) = fixture()?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'budget'",
        [],
    )?;
    assert!(
        matches!(SqliteAuthorityStore::open_serving(&database, &locks), Err(SqliteServingOwnerError::Invalid(message))
        if message == "schema namespace budget is missing")
    );
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM chio_store_schema_versions WHERE store_key = 'budget')",
        [],
        |row| row.get(0),
    )?;
    assert!(!present);
    Ok(())
}

#[test]
fn serving_reopen_refuses_missing_lease_table_without_repair() -> TestResult {
    let (_root, database, locks) = fixture()?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("DROP TABLE chio_serving_leases;")?;
    assert!(
        matches!(SqliteAuthorityStore::open_serving(&database, &locks), Err(SqliteServingOwnerError::Invalid(message))
        if message == "serving lease schema differs from the canonical definition")
    );
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_serving_leases')",
        [],
        |row| row.get(0),
    )?;
    assert!(!present);
    Ok(())
}
