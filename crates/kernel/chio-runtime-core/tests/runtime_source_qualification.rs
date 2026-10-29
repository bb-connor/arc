#![cfg(unix)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStore, RuntimeSourcePort,
};
use chio_runtime_core::{RuntimeAdmissionStore, SqliteRuntimeOrchestrationStore};
use chio_store_sqlite::SqliteAuthorityStore;

#[test]
fn fresh_operation_owned_source_qualification_has_no_retired_replay_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let database = directory.path().join("authority.sqlite3");
    let locks = directory.path().join("locks");
    std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let clock = chio_test_support::clock::clock();
    let authority =
        SqliteAuthorityStore::open_serving_with_clock(&database, &locks, clock.clone())?;
    let source_path = directory.path().join("runtime.sqlite3");
    let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let now = clock.unix_millis()?.get();
    let runtime = AdmissionIdentifier::try_new("runtime", "fresh-runtime")?;
    let installed = store.install_runtime_source(
        &AdmissionIdentifier::try_new("source", "fresh-source")?,
        &runtime,
        &source,
        &fence,
        now,
    )?;
    let repeated = store.install_runtime_source(
        &AdmissionIdentifier::try_new("source", "fresh-source")?,
        &runtime,
        &source,
        &fence,
        now,
    )?;
    assert_eq!(installed, repeated);
    let binding =
        RuntimeParticipantAuthorityBindingV1::new(runtime, installed.qualification_id().clone());
    let qualified = store.load_runtime_source_qualification(&binding, &fence, now)?;
    source.verify_operation_owned_runtime_source(&qualified)?;
    assert_eq!(qualified.source_id(), "fresh-source");
    assert_eq!(qualified.runtime_authority_id(), "fresh-runtime");
    assert_eq!(qualified.destination_authority_id(), fence.store_uuid);

    let other = SqliteRuntimeOrchestrationStore::open(directory.path().join("other.sqlite3"))?;
    let error = other
        .verify_operation_owned_runtime_source(&qualified)
        .err()
        .ok_or("another physical source accepted the qualified binding")?;
    assert_eq!(error.code(), "runtime_source_qualification_invalid");

    let source_raw = rusqlite::Connection::open(&source_path)?;
    let retired_source_objects: i64 = source_raw.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE name IN ('runtime_consumed_leases', 'runtime_consumed_treaty_continuations',
                        'runtime_consumed_swarm_continuations', 'runtime_replay_source_seal')
            OR name GLOB 'runtime_replay_source_*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retired_source_objects, 0);
    let destination_raw = rusqlite::Connection::open(&database)?;
    let retired_destination_objects: i64 = destination_raw.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE name GLOB 'runtime_replay_migration_*'
            OR name = 'runtime_replay_legacy_tombstones'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retired_destination_objects, 0);
    Ok(())
}

#[test]
fn unsupported_source_schema_refuses_without_adoption() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let valid_path = directory.path().join("valid.sqlite3");
    drop(SqliteRuntimeOrchestrationStore::open(&valid_path)?);
    drop(SqliteRuntimeOrchestrationStore::open(&valid_path)?);
    for (name, sql) in [
        ("retired", "CREATE TABLE runtime_consumed_leases (lease_id TEXT PRIMARY KEY, admission_id TEXT)"),
        ("partial", "CREATE TABLE runtime_source_qualification (singleton INTEGER PRIMARY KEY, canonical_bytes BLOB)"),
        ("unknown", "CREATE TABLE unexpected_state (value TEXT)"),
    ] {
        let path = directory.path().join(format!("{name}.sqlite3"));
        let raw = rusqlite::Connection::open(&path)?;
        raw.execute_batch(sql)?;
        let before: i64 = raw.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        let error = SqliteRuntimeOrchestrationStore::open(&path)
            .err().ok_or("unsupported runtime schema was adopted")?;
        assert_eq!(error.code(), "runtime_store_schema_mismatch");
        let after: i64 = raw.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        assert_eq!(before, after);
        let version: i64 = raw.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, 0);
    }
    Ok(())
}

#[test]
fn source_qualification_reopen_and_physical_identity_are_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite3");
    let source_id = AdmissionIdentifier::try_new("source", "source")?;
    let runtime_id = AdmissionIdentifier::try_new("runtime", "runtime")?;
    let destination_id = AdmissionIdentifier::try_new("destination", "destination")?;
    let source = SqliteRuntimeOrchestrationStore::open(&path)?;
    let qualified = source.qualify(&source_id, &runtime_id, &destination_id)?;
    assert_eq!(
        source.qualify(&source_id, &runtime_id, &destination_id)?,
        qualified
    );
    source.verify_exact(&qualified)?;
    drop(source);
    let source = SqliteRuntimeOrchestrationStore::open(&path)?;
    source.verify_exact(&qualified)?;
    let other_destination = AdmissionIdentifier::try_new("destination", "other")?;
    let error = source
        .qualify(&source_id, &runtime_id, &other_destination)
        .err()
        .ok_or("source qualification changed destination")?;
    assert_eq!(error, chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
        "runtime admission rejected: runtime_source_qualification_invalid: runtime source is bound to another qualification".into(),
    ));
    source.verify_exact(&qualified)?;
    drop(source);
    let copy = directory.path().join("copy.sqlite3");
    std::fs::copy(&path, &copy)?;
    let error = SqliteRuntimeOrchestrationStore::open(&copy)
        .err()
        .ok_or("copied source retained physical qualification")?;
    assert_eq!(error.code(), "runtime_source_qualification_invalid");
    let source = SqliteRuntimeOrchestrationStore::open(&path)?;
    let link = directory.path().join("hardlink.sqlite3");
    std::fs::hard_link(&path, &link)?;
    let error = source
        .verify_operation_owned_runtime_source(&qualified)
        .err()
        .ok_or("hard-linked source retained qualification")?;
    assert_eq!(error.code(), "runtime_source_qualification_invalid");
    Ok(())
}
