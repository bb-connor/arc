use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStore, RuntimeSourcePort, RuntimeSourceQualificationV1,
};
use chio_store_sqlite::SqliteAuthorityStore;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ROLLED_BACK: &str = "runtime_source_rolled_back";

fn open_source(database: &Path) -> Result<SqliteRuntimeOrchestrationStore, ChioRuntimeError> {
    SqliteRuntimeOrchestrationStore::open(database)
}

fn floor(version: u64, bundle: char) -> RuntimeTrustFloorEntry {
    RuntimeTrustFloorEntry {
        verifier_id: "verifier-rollback".to_owned(),
        key_id: "key-rollback".to_owned(),
        highest_version: version,
        latest_bundle_sha256: bundle.to_string().repeat(64),
        latest_revocation_checkpoint_sha256: "e".repeat(64),
    }
}

fn qualify(store: &SqliteRuntimeOrchestrationStore) -> TestResult<RuntimeSourceQualificationV1> {
    Ok(store.qualify(
        &AdmissionIdentifier::try_new("source", "rollback-source")?,
        &AdmissionIdentifier::try_new("runtime", "rollback-runtime")?,
        &AdmissionIdentifier::try_new("destination", "rollback-destination")?,
    )?)
}

/// A consistent standalone image of the live database, as a backup tool
/// would take it.
fn snapshot(database: &Path, image: &Path) -> TestResult {
    let connection = rusqlite::Connection::open(database)?;
    let image = image.to_str().ok_or("snapshot path is not UTF-8")?;
    connection.execute("VACUUM INTO ?1", [image])?;
    Ok(())
}

fn physical_identity(database: &Path) -> TestResult<(u64, u64, u64)> {
    let metadata = fs::metadata(database)?;
    Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
}

/// Write an older image over the database file in place, keeping its device,
/// inode and link count, after the store that owned it has closed.
fn restore_in_place(database: &Path, image: &Path) -> TestResult {
    let before = physical_identity(database)?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = database.with_file_name(format!(
            "{}{suffix}",
            database
                .file_name()
                .ok_or("database has no file name")?
                .to_string_lossy()
        ));
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    let bytes = fs::read(image)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(database)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    assert_eq!(
        before,
        physical_identity(database)?,
        "the restore must preserve the physical identity qualification binds"
    );
    Ok(())
}

/// Restore every table of an older image through a second SQLite connection
/// while the store stays open, then checkpoint the WAL into the database
/// file. The qualification row is immutable and identical in both images.
fn restore_under_live_store(database: &Path, image: &Path) -> TestResult {
    let before = physical_identity(database)?;
    let mut connection = rusqlite::Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let image = image.to_str().ok_or("image path is not UTF-8")?;
    connection.execute("ATTACH DATABASE ?1 AS older", [image])?;
    let tables = {
        let mut statement = connection.prepare(
            "SELECT name FROM older.sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
               AND name <> 'runtime_source_qualification'
             ORDER BY name",
        )?;
        let names = statement.query_map([], |row| row.get::<_, String>(0))?;
        names.collect::<Result<Vec<_>, _>>()?
    };
    assert!(tables.iter().any(|table| table == "runtime_trust_floors"));
    let unchanged: bool = connection.query_row(
        "SELECT NOT EXISTS (
             SELECT * FROM main.runtime_source_qualification
             EXCEPT SELECT * FROM older.runtime_source_qualification)
         AND NOT EXISTS (
             SELECT * FROM older.runtime_source_qualification
             EXCEPT SELECT * FROM main.runtime_source_qualification)",
        [],
        |row| row.get(0),
    )?;
    assert!(unchanged, "both images must carry the same qualification");
    let transaction = connection.transaction()?;
    for table in &tables {
        transaction.execute_batch(&format!(
            "DELETE FROM main.\"{table}\"; INSERT INTO main.\"{table}\" SELECT * FROM older.\"{table}\";"
        ))?;
    }
    transaction.commit()?;
    connection.execute_batch("DETACH DATABASE older; PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    assert_eq!(
        before,
        physical_identity(database)?,
        "the restore must preserve the physical identity qualification binds"
    );
    Ok(())
}

fn raw_floor_version(database: &Path) -> TestResult<i64> {
    let connection = rusqlite::Connection::open(database)?;
    Ok(connection.query_row(
        "SELECT highest_version FROM runtime_trust_floors
         WHERE verifier_id = 'verifier-rollback' AND key_id = 'key-rollback'",
        [],
        |row| row.get(0),
    )?)
}

fn raw_bundle_count(database: &Path, admission_id: &str) -> TestResult<i64> {
    let connection = rusqlite::Connection::open(database)?;
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM runtime_admission_bundles WHERE admission_id = ?1",
        [admission_id],
        |row| row.get(0),
    )?)
}

fn rolled_back(result: Result<SqliteRuntimeOrchestrationStore, ChioRuntimeError>) -> TestResult {
    let error = result
        .err()
        .ok_or("a restored older runtime source image reopened")?;
    assert_eq!(error.code(), ROLLED_BACK);
    Ok(())
}

#[test]
fn reopen_without_restore_keeps_serving() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime.sqlite3");
    let store = open_source(&database)?;
    let qualified = qualify(&store)?;
    store.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    store.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;
    drop(store);

    let store = open_source(&database)?;
    store.verify_exact(&qualified)?;
    let current = store
        .runtime_trust_floor("verifier-rollback", "key-rollback")?
        .ok_or("trust floor lost across reopen")?;
    assert_eq!(current.highest_version, 2);
    Ok(())
}

#[test]
fn in_place_restore_of_an_older_trust_floor_image_refuses_open() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime.sqlite3");
    let image = directory.path().join("older.sqlite3");
    let store = open_source(&database)?;
    qualify(&store)?;
    store.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    snapshot(&database, &image)?;
    store.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;
    drop(store);

    restore_in_place(&database, &image)?;
    assert_eq!(raw_floor_version(&database)?, 1);
    rolled_back(open_source(&database))
}

#[test]
fn in_place_restore_cannot_forget_a_consumed_admission_bundle() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime.sqlite3");
    let image = directory.path().join("older.sqlite3");
    let store = open_source(&database)?;
    qualify(&store)?;
    snapshot(&database, &image)?;
    let consumed = bundle();
    store.insert_bundle(consumed.clone())?;
    assert!(store.bundle(&consumed.admission_id)?.is_some());
    drop(store);

    restore_in_place(&database, &image)?;
    assert_eq!(raw_bundle_count(&database, &consumed.admission_id)?, 0);
    rolled_back(open_source(&database))
}

#[test]
fn restored_image_with_a_trust_floor_edited_past_the_live_head_still_refuses() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime.sqlite3");
    let image = directory.path().join("older.sqlite3");
    let store = open_source(&database)?;
    qualify(&store)?;
    store.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    snapshot(&database, &image)?;
    store.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;
    drop(store);

    restore_in_place(&database, &image)?;
    assert_eq!(raw_floor_version(&database)?, 1);
    let forked = floor(3, 'f');
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute(
        "UPDATE runtime_trust_floors
         SET highest_version = ?1, latest_bundle_sha256 = ?2
         WHERE verifier_id = ?3 AND key_id = ?4",
        rusqlite::params![
            i64::try_from(forked.highest_version)?,
            forked.latest_bundle_sha256,
            forked.verifier_id,
            forked.key_id
        ],
    )?;
    drop(connection);
    assert_eq!(raw_floor_version(&database)?, 3);
    rolled_back(open_source(&database))
}

#[test]
fn admission_refuses_a_qualified_source_restored_under_a_live_store() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let authority_database = directory.path().join("authority.sqlite3");
    let locks = directory.path().join("locks");
    fs::DirBuilder::new().mode(0o700).create(&locks)?;
    SqliteAuthorityStore::provision(&authority_database, &locks)?;
    let clock = chio_test_support::clock::clock();
    let authority =
        SqliteAuthorityStore::open_serving_with_clock(&authority_database, &locks, clock.clone())?;
    let database = directory.path().join("runtime.sqlite3");
    let image = directory.path().join("older.sqlite3");
    let source = open_source(&database)?;
    let operations = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let now = clock.unix_millis()?.get();
    let runtime = AdmissionIdentifier::try_new("runtime", "rollback-runtime")?;
    let installed = operations.install_runtime_source(
        &AdmissionIdentifier::try_new("source", "rollback-source")?,
        &runtime,
        &source,
        &fence,
        now,
    )?;
    let binding =
        RuntimeParticipantAuthorityBindingV1::new(runtime, installed.qualification_id().clone());
    let qualified = operations.load_runtime_source_qualification(&binding, &fence, now)?;
    source.verify_operation_owned_runtime_source(&qualified)?;
    source.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    snapshot(&database, &image)?;
    source.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;

    restore_under_live_store(&database, &image)?;
    assert_eq!(raw_floor_version(&database)?, 1);
    let served = source
        .runtime_trust_floor("verifier-rollback", "key-rollback")?
        .ok_or("the live store lost its trust floor")?;
    assert_eq!(
        served.highest_version, 1,
        "the open store must observe the restored image"
    );
    let error = source
        .verify_operation_owned_runtime_source(&qualified)
        .err()
        .ok_or("admission accepted a runtime source restored under a live store")?;
    assert_eq!(error.code(), ROLLED_BACK);
    Ok(())
}
