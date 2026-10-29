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

/// Write an older image over the database file in place, keeping its device,
/// inode and link count, after the store that owned it has closed.
fn restore_in_place(database: &Path, image: &Path) -> TestResult {
    let before = fs::metadata(database)?;
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
    let after = fs::metadata(database)?;
    assert_eq!(
        (before.dev(), before.ino(), before.nlink()),
        (after.dev(), after.ino(), after.nlink()),
        "the restore must preserve the physical identity qualification binds"
    );
    Ok(())
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
    let store = SqliteRuntimeOrchestrationStore::open(&database)?;
    let qualified = qualify(&store)?;
    store.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    store.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;
    drop(store);

    let store = SqliteRuntimeOrchestrationStore::open(&database)?;
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
    let store = SqliteRuntimeOrchestrationStore::open(&database)?;
    qualify(&store)?;
    store.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    snapshot(&database, &image)?;
    store.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;
    drop(store);

    restore_in_place(&database, &image)?;
    rolled_back(SqliteRuntimeOrchestrationStore::open(&database))
}

#[test]
fn in_place_restore_cannot_forget_a_consumed_admission_bundle() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime.sqlite3");
    let image = directory.path().join("older.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&database)?;
    qualify(&store)?;
    snapshot(&database, &image)?;
    let consumed = bundle();
    store.insert_bundle(consumed.clone())?;
    assert!(store.bundle(&consumed.admission_id)?.is_some());
    drop(store);

    restore_in_place(&database, &image)?;
    rolled_back(SqliteRuntimeOrchestrationStore::open(&database))
}

#[test]
fn restored_image_edited_past_the_live_head_still_refuses() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime.sqlite3");
    let image = directory.path().join("older.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&database)?;
    qualify(&store)?;
    store.validate_and_record_runtime_trust_floor(floor(1, 'a'), None)?;
    snapshot(&database, &image)?;
    store.validate_and_record_runtime_trust_floor(floor(2, 'b'), Some(&"a".repeat(64)))?;
    drop(store);

    restore_in_place(&database, &image)?;
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
    rolled_back(SqliteRuntimeOrchestrationStore::open(&database))
}

#[test]
fn admission_refuses_a_qualified_source_restored_in_place() -> TestResult {
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
    let source = SqliteRuntimeOrchestrationStore::open(&database)?;
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
    drop(source);

    restore_in_place(&database, &image)?;
    let reopened = match SqliteRuntimeOrchestrationStore::open(&database) {
        Ok(reopened) => reopened,
        Err(error) => {
            assert_eq!(error.code(), ROLLED_BACK);
            return Ok(());
        }
    };
    let error = reopened
        .verify_operation_owned_runtime_source(&qualified)
        .err()
        .ok_or("admission accepted a restored older runtime source")?;
    assert_eq!(error.code(), ROLLED_BACK);
    Ok(())
}
