use chio_security_types::ports::PortErrorKind;
use chio_store_sqlite::{BlobStoreError, SqliteEncryptedBlobStore, SqliteSecurityStateStore};
use rusqlite::Connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn fresh_security_blob_composite_reopens_through_both_readers() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(SqliteSecurityStateStore::open(&path)?);
    drop(SqliteSecurityStateStore::open(&path)?);
    drop(SqliteEncryptedBlobStore::open(&path)?);
    let connection = Connection::open(&path)?;
    let mut statement = connection
        .prepare("SELECT store_key, version FROM chio_store_schema_versions ORDER BY store_key")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(
        rows,
        vec![("encrypted_blob".into(), 1), ("security_state".into(), 1)]
    );
    Ok(())
}

#[test]
fn composite_readers_refuse_a_missing_namespace_without_repair() -> TestResult {
    for missing in ["encrypted_blob", "security_state"] {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("security.db");
        drop(SqliteSecurityStateStore::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute(
            "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
            [missing],
        )?;
        let error = SqliteSecurityStateStore::open(&path)
            .err()
            .ok_or("missing namespace accepted")?;
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
        assert!(
            matches!(SqliteEncryptedBlobStore::open(&path), Err(BlobStoreError::Sqlite(message))
            if message == format!("schema namespace {missing} is missing"))
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM chio_store_schema_versions WHERE store_key = ?1",
                [missing],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    Ok(())
}

#[test]
fn standalone_blob_reopens_and_cannot_be_promoted_to_security_composite() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("blobs.db");
    drop(SqliteEncryptedBlobStore::open(&path)?);
    drop(SqliteEncryptedBlobStore::open(&path)?);
    let connection = Connection::open(&path)?;
    let before: i64 = connection.pragma_query_value(None, "schema_version", |row| row.get(0))?;
    let error = SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("standalone blob database was promoted")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(
        connection.pragma_query_value(None, "schema_version", |row| row.get::<_, i64>(0))?,
        before
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM chio_store_schema_versions",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    Ok(())
}
