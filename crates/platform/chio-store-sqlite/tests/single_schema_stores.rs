use std::path::Path;

use chio_store_sqlite::{BlobStoreError, SqliteEncryptedBlobStore, SqliteMemoryProvenanceStore};
use rusqlite::Connection;

const STALE_SCHEMA: &str =
    "database schema version 0 is not the current schema version 1; refusing to open";

fn restamp(path: &Path, store_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = ?1",
        [store_key],
    )?;
    connection.execute_batch("PRAGMA ignore_check_constraints = OFF;")?;
    Ok(())
}

fn stamped_version(path: &Path, store_key: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let connection = Connection::open(path)?;
    Ok(connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
        [store_key],
        |row| row.get(0),
    )?)
}

#[test]
fn encrypted_blob_store_refuses_an_obsolete_schema() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("blobs.sqlite");
    drop(SqliteEncryptedBlobStore::open(&path)?);
    restamp(&path, "encrypted_blob")?;
    let error = SqliteEncryptedBlobStore::open(&path)
        .err()
        .ok_or("an obsolete encrypted blob schema opened")?;
    assert!(matches!(&error, BlobStoreError::Sqlite(message) if message == STALE_SCHEMA));
    assert_eq!(stamped_version(&path, "encrypted_blob")?, 0);
    Ok(())
}

#[test]
fn memory_provenance_store_refuses_an_obsolete_schema() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("provenance.sqlite");
    drop(SqliteMemoryProvenanceStore::open(&path)?);
    restamp(&path, "memory_provenance")?;
    let error = SqliteMemoryProvenanceStore::open(&path)
        .err()
        .ok_or("an obsolete memory provenance schema opened")?;
    assert_eq!(
        error.to_string(),
        format!("sqlite memory provenance store error: {STALE_SCHEMA}")
    );
    assert_eq!(stamped_version(&path, "memory_provenance")?, 0);
    Ok(())
}
