#![cfg(unix)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
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
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        chio_test_support::clock::clock(),
    )?;
    let source_path = directory.path().join("runtime.sqlite3");
    let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let runtime = AdmissionIdentifier::try_new("runtime", "fresh-runtime")?;
    let expected = store.expect_runtime_replay_source(
        &AdmissionIdentifier::try_new("source", "fresh-source")?,
        &runtime,
        &source,
        &fence,
        now,
    )?;
    store.import_runtime_replay_source(
        &runtime,
        expected.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    let binding =
        RuntimeParticipantAuthorityBindingV1::new(runtime, expected.expectation_id().clone());
    store.activate_runtime_replay_source(&binding, &source, &fence, now)?;
    let qualified = store.load_runtime_participant_activation(&binding, &fence, now)?;
    source.verify_operation_owned_replay_source(&qualified)?;
    assert_eq!(qualified.source_id(), "fresh-source");
    assert_eq!(qualified.runtime_authority_id(), "fresh-runtime");
    assert_eq!(qualified.destination_authority_id(), fence.store_uuid);

    let other = SqliteRuntimeOrchestrationStore::open(directory.path().join("other.sqlite3"))?;
    let error = other
        .verify_operation_owned_replay_source(&qualified)
        .err()
        .ok_or("another physical source accepted the qualified binding")?;
    assert_eq!(error.code(), "runtime_replay_source_invalid");

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
