//! Existing enabled reference corruption is distinct from ordinary absence.
use chio_store_sqlite::{
    BlobReference, BlobStoreError, SqliteEncryptedBlobStore, TenantId, TenantKey,
};
use rusqlite::{Connection, OpenFlags};
use std::{error::Error, path::PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type ReferenceRows = Vec<(String, String, Vec<u8>, String, i64)>;

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: SqliteEncryptedBlobStore,
    reference: BlobReference,
    key: TenantKey,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("reference-integrity.sqlite3");
        let store = SqliteEncryptedBlobStore::open(&path)?;
        let reference = BlobReference::new(
            "chio.secret-broker.credentials.v1",
            TenantId::new("resolver-tenant"),
            [93; 32],
        )?;
        Ok(Self {
            _directory: directory,
            path,
            store,
            reference,
            key: TenantKey::from_bytes([94; 32]),
        })
    }

    fn provision(&self) -> TestResult<chio_store_sqlite::BlobHandle> {
        Ok(self
            .store
            .write_encrypted_blob_with_reference_once(
                &self.reference,
                &self.key,
                b"private-resolver-canary",
                &"11".repeat(32),
                &"22".repeat(32),
            )?
            .0)
    }

    fn fault(&self, sql: &str) -> TestResult {
        let independent = Connection::open(&self.path)?;
        independent.execute_batch("PRAGMA foreign_keys = OFF;")?;
        assert_eq!(
            independent.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?,
            0
        );
        independent.execute_batch(sql)?;
        Ok(())
    }

    fn reference_snapshot(&self) -> TestResult<(ReferenceRows, i64)> {
        let connection = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut statement = connection.prepare(
            "SELECT namespace, tenant_id, reference_key, blob_id, enabled
             FROM chio_encrypted_blob_references ORDER BY namespace, tenant_id, reference_key",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<Result<ReferenceRows, _>>()?;
        let mutations = connection.query_row(
            "SELECT COUNT(*) FROM chio_encrypted_blob_reference_mutations",
            [],
            |row| row.get(0),
        )?;
        Ok((rows, mutations))
    }
}

#[test]
fn f011_reference_integrity_valid_reference_resolves_without_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let handle = fixture.provision()?;
    let before = fixture.reference_snapshot()?;
    assert_eq!(
        fixture.store.resolve_blob_reference(&fixture.reference)?,
        handle
    );
    assert_eq!(
        fixture.store.read_encrypted_blob(&handle, &fixture.key)?,
        b"private-resolver-canary"
    );
    assert_eq!(fixture.reference_snapshot()?, before);
    Ok(())
}

#[test]
fn f011_reference_integrity_absent_reference_stays_not_found_without_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let before = fixture.reference_snapshot()?;
    let error = fixture
        .store
        .resolve_blob_reference(&fixture.reference)
        .err()
        .ok_or("absent reference resolved")?;
    assert!(
        matches!(error, BlobStoreError::NotFound),
        "ordinary miss changed category: {error}"
    );
    assert_eq!(fixture.reference_snapshot()?, before);
    Ok(())
}

#[test]
fn f011_reference_integrity_disabled_reference_stays_not_found_and_retains_blob() -> TestResult {
    let fixture = Fixture::new()?;
    let handle = fixture.provision()?;
    fixture.store.disable_blob_reference_once(
        &fixture.reference,
        &"33".repeat(32),
        &"44".repeat(32),
    )?;
    let before = fixture.reference_snapshot()?;
    let error = fixture
        .store
        .resolve_blob_reference(&fixture.reference)
        .err()
        .ok_or("disabled reference resolved")?;
    assert!(
        matches!(error, BlobStoreError::NotFound),
        "disabled reference changed category: {error}"
    );
    assert_eq!(
        fixture.store.read_encrypted_blob(&handle, &fixture.key)?,
        b"private-resolver-canary"
    );
    assert_eq!(fixture.reference_snapshot()?, before);
    Ok(())
}

fn invalid_parent(sql: &str) -> TestResult {
    let fixture = Fixture::new()?;
    fixture.provision()?;
    fixture.fault(sql)?;
    let before = fixture.reference_snapshot()?;
    assert_eq!(before.0.len(), 1);
    assert_eq!(before.0[0].4, 1);
    let error = fixture
        .store
        .resolve_blob_reference(&fixture.reference)
        .err()
        .ok_or("corrupt parent reference resolved")?;
    assert!(
        matches!(error, BlobStoreError::InvalidReference),
        "existing enabled reference corruption became ordinary absence: {error}"
    );
    assert_eq!(fixture.reference_snapshot()?, before);
    Ok(())
}

#[test]
fn f011_reference_integrity_missing_parent_is_invalid_reference() -> TestResult {
    invalid_parent("DELETE FROM chio_encrypted_blobs;")
}

#[test]
fn f011_reference_integrity_wrong_tenant_parent_is_invalid_reference() -> TestResult {
    invalid_parent("UPDATE chio_encrypted_blobs SET tenant_id = 'foreign-resolver-tenant';")
}

#[test]
fn f011_reference_integrity_missing_parent_table_remains_sqlite() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.provision()?;
    fixture.fault("DROP TABLE chio_encrypted_blobs;")?;
    let before = fixture.reference_snapshot()?;
    let error = fixture
        .store
        .resolve_blob_reference(&fixture.reference)
        .err()
        .ok_or("missing mandatory table became success")?;
    assert!(
        matches!(error, BlobStoreError::Sqlite(_)),
        "missing table lost native SQLite store category: {error}"
    );
    assert_eq!(fixture.reference_snapshot()?, before);
    Ok(())
}
