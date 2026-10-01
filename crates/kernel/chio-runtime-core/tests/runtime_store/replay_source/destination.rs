//! Real source-to-qualified-destination migration. Retained markers are
//! unresolved historical evidence, not ownership by an admission operation.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::admission_operation::{AdmissionIdentifier, RuntimeReplaySourcePort};
use chio_store_sqlite::{RuntimeReplayMigrationRecordV1, SqliteAuthorityStore};

use super::*;

#[path = "destination/import_serialization.rs"]
mod import_serialization;

#[test]
fn real_activated_source_and_destination_survive_owner_restart_without_resealing() -> TestResult {
    use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
    use chio_kernel::admission_operation::AdmissionOperationStore;
    let (directory, database, lock_root, authority) = destination_fixture()?;
    let source_path = directory.path().join("activated-runtime.sqlite3");
    let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    seed_inventory(&source)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let runtime_id = AdmissionIdentifier::try_new("runtime", "activated-runtime")?;
    let expected = store.expect_runtime_replay_source(
        &AdmissionIdentifier::try_new("source", "activated-source")?,
        &runtime_id,
        &source,
        &fence,
        now_ms()?,
    )?;
    store.import_runtime_replay_source(
        &runtime_id,
        expected.expectation_id(),
        &source,
        &fence,
        now_ms()?,
    )?;
    let binding = RuntimeParticipantAuthorityBindingV1::new(
        runtime_id.clone(),
        expected.expectation_id().clone(),
    );
    let active = store.activate_runtime_replay_source(&binding, &source, &fence, now_ms()?)?;
    assert_eq!(active.event_sequence(), 3);
    assert_all_legacy_kinds_blocked(&source);
    drop(store);
    drop(authority);
    drop(source);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    let current = authority.mutation_fence();
    assert!(current.owner_epoch > fence.owner_epoch);
    assert!(store
        .load_runtime_participant_activation(&binding, &fence, now_ms()?)
        .is_err());
    let snapshot = store.load_runtime_participant_activation(&binding, &current, now_ms()?)?;
    source.verify_operation_owned_replay_source(&snapshot)?;
    assert_eq!(snapshot, *expected.snapshot());
    assert_eq!(
        store.activate_runtime_replay_source(&binding, &source, &current, now_ms()?)?,
        active
    );
    assert_eq!(
        store.load_runtime_replay_migration(&runtime_id, &current, now_ms()?)?,
        Some(active)
    );
    assert_all_legacy_kinds_blocked(&source);
    let raw = Connection::open(database)?;
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM runtime_replay_migration_events",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        3
    );
    Ok(())
}

fn destination_fixture() -> TestResult<(tempfile::TempDir, PathBuf, PathBuf, SqliteAuthorityStore)>
{
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let database = directory.path().join("qualified-authority.sqlite3");
    let lock_root = directory.path().join("locks");
    std::fs::DirBuilder::new().mode(0o700).create(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    Ok((directory, database, lock_root, authority))
}

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn source_binding(
    record: &RuntimeReplayMigrationRecordV1,
) -> TestResult<RuntimeReplaySourceBinding> {
    Ok(RuntimeReplaySourceBinding::new(
        record.snapshot().source_id().to_owned(),
        record.snapshot().runtime_authority_id().to_owned(),
        record.snapshot().destination_authority_id().to_owned(),
    )?)
}

fn assert_destination_history(
    raw: &Connection,
    record: &RuntimeReplayMigrationRecordV1,
) -> TestResult {
    let runtime_authority = record.snapshot().runtime_authority_id();
    let expectations: i64 = raw.query_row(
        "SELECT COUNT(*) FROM runtime_replay_migration_expectations WHERE runtime_authority_id = ?1",
        [runtime_authority],
        |row| row.get(0),
    )?;
    assert_eq!(
        expectations, 1,
        "even an empty source reserves a generation"
    );
    let events: i64 = raw.query_row(
        "SELECT COUNT(*) FROM runtime_replay_migration_events WHERE runtime_authority_id = ?1",
        [runtime_authority],
        |row| row.get(0),
    )?;
    assert_eq!(events, i64::try_from(record.event_sequence())?);
    let global_events: i64 = raw.query_row(
        "SELECT COUNT(*) FROM authority_global_commits
         WHERE projection_kind = 'runtime_replay_migration' AND projection_key = ?1",
        [runtime_authority],
        |row| row.get(0),
    )?;
    assert_eq!(global_events, events);

    let tombstones: i64 = raw.query_row(
        "SELECT COUNT(*) FROM runtime_replay_legacy_tombstones WHERE runtime_authority_id = ?1",
        [runtime_authority],
        |row| row.get(0),
    )?;
    let markers = if record.imported_inactive() {
        record.snapshot().markers()
    } else {
        &[]
    };
    assert_eq!(tombstones, i64::try_from(markers.len())?);
    for marker in markers {
        let matches: i64 = raw.query_row(
            "SELECT COUNT(*) FROM runtime_replay_legacy_tombstones
             WHERE runtime_authority_id = ?1 AND participant_kind = ?2 AND resource_id = ?3
               AND source_id = ?4 AND expectation_id = ?5 AND historical_admission_id = ?6",
            params![
                runtime_authority,
                marker.kind().as_str(),
                marker.resource_id(),
                record.snapshot().source_id(),
                record.expectation_id().as_str(),
                marker.historical_admission_id(),
            ],
            |row| row.get(0),
        )?;
        assert_eq!(
            matches, 1,
            "retain the exact historical owner, not a new operation"
        );
    }
    let operations: i64 =
        raw.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| {
            row.get(0)
        })?;
    assert_eq!(
        operations, 0,
        "import must not synthesize an admission owner"
    );
    Ok(())
}

fn assert_all_legacy_kinds_blocked(source: &SqliteRuntimeOrchestrationStore) {
    for result in [
        source.consume_destructive_lease("late-resource", "late-admission"),
        source.consume_treaty_continuation("late-resource", "late-admission"),
        source.consume_swarm_continuation("late-resource", "late-admission"),
        source.release_destructive_lease("resource-a", "admission-lease"),
        source.release_treaty_continuation("resource-a", "admission-treaty"),
        source.release_swarm_continuation("resource-a", "admission-swarm"),
    ] {
        assert_code(result, "runtime_replay_source_sealed");
    }
}

fn import_exact_source_and_reopen(populated: bool) -> TestResult {
    let (directory, database, lock_root, authority) = destination_fixture()?;
    let source_path = directory.path().join("legacy-source.sqlite3");
    let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    if populated {
        seed_inventory(&source)?;
    }
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let source_id = AdmissionIdentifier::try_new("source_id", "real-sqlite-source")?;
    let runtime_authority = AdmissionIdentifier::try_new("runtime_authority_id", "real-runtime")?;
    let expected = store.expect_runtime_replay_source(
        &source_id,
        &runtime_authority,
        &source,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(expected.event_sequence(), 1);
    assert!(!expected.imported_inactive());
    assert_eq!(
        expected.snapshot().destination_authority_id(),
        fence.store_uuid
    );
    assert_eq!(expected.snapshot().source_id(), source_id.as_str());
    assert_eq!(
        expected.snapshot().runtime_authority_id(),
        runtime_authority.as_str()
    );
    assert_eq!(
        expected.snapshot().markers().len(),
        if populated { 6 } else { 0 }
    );
    let binding = source_binding(&expected)?;
    assert!(source.load_legacy_replay_source_seal(&binding)?.is_none());
    assert!(RuntimeReplaySourcePort::verify_exact(&source, expected.snapshot()).is_err());
    {
        let raw = Connection::open(&database)?;
        assert_destination_history(&raw, &expected)?;
    }

    let imported = store.import_runtime_replay_source(
        &runtime_authority,
        expected.expectation_id(),
        &source,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(imported.event_sequence(), 2);
    assert!(imported.imported_inactive());
    assert_eq!(imported.snapshot(), expected.snapshot());
    assert_eq!(imported.expectation_id(), expected.expectation_id());
    let seal = source
        .load_legacy_replay_source_seal(&binding)?
        .ok_or("source seal missing after destination import")?;
    assert_eq!(
        seal.canonical_bytes()?.as_slice(),
        expected.snapshot().canonical_bytes()
    );
    if populated {
        assert_inventory(&seal);
    }
    RuntimeReplaySourcePort::verify_exact(&source, imported.snapshot())?;
    assert_all_legacy_kinds_blocked(&source);
    assert_eq!(
        store.expect_runtime_replay_source(
            &source_id,
            &runtime_authority,
            &source,
            &fence,
            now_ms()?
        )?,
        imported,
    );
    assert_eq!(
        store.import_runtime_replay_source(
            &runtime_authority,
            expected.expectation_id(),
            &source,
            &fence,
            now_ms()?,
        )?,
        imported,
    );
    {
        let raw = Connection::open(&database)?;
        assert_destination_history(&raw, &imported)?;
    }
    drop(store);
    drop(authority);
    drop(source);

    let reopened_authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let reopened_fence = reopened_authority.mutation_fence();
    assert_eq!(reopened_fence.store_uuid, fence.store_uuid);
    assert!(reopened_fence.owner_epoch > fence.owner_epoch);
    let reopened_store = reopened_authority.admission_operation_store();
    let reopened_source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    assert_eq!(
        reopened_store.load_runtime_replay_migration(
            &runtime_authority,
            &reopened_fence,
            now_ms()?
        )?,
        Some(imported.clone()),
    );
    assert_eq!(
        reopened_store.import_runtime_replay_source(
            &runtime_authority,
            expected.expectation_id(),
            &reopened_source,
            &reopened_fence,
            now_ms()?,
        )?,
        imported,
    );
    RuntimeReplaySourcePort::verify_exact(&reopened_source, expected.snapshot())?;
    assert_all_legacy_kinds_blocked(&reopened_source);
    assert_destination_history(&Connection::open(&database)?, &imported)?;
    Ok(())
}

#[test]
fn qualified_destination_imports_complete_source_as_inactive_history() -> TestResult {
    import_exact_source_and_reopen(true)
}

#[test]
fn qualified_destination_reserves_and_imports_empty_source_generation() -> TestResult {
    import_exact_source_and_reopen(false)
}

#[test]
fn qualified_empty_pin_rejects_later_markers_without_sealing_or_importing() -> TestResult {
    for (table, key, _) in TABLES {
        let (directory, database, _lock_root, authority) = destination_fixture()?;
        let source_path = directory.path().join("changed-source.sqlite3");
        let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        let source_id = AdmissionIdentifier::try_new("source_id", "changing-source")?;
        let runtime_authority = AdmissionIdentifier::try_new("runtime_authority_id", "runtime")?;
        let expected = store.expect_runtime_replay_source(
            &source_id,
            &runtime_authority,
            &source,
            &fence,
            now_ms()?,
        )?;
        let raw_source = Connection::open(&source_path)?;
        raw_source.execute(
            &format!("INSERT INTO {table}({key}, admission_id) VALUES (?1, ?2)"),
            params!["late-resource", "historical-owner"],
        )?;
        let changed = raw_snapshot(&raw_source)?;
        assert!(store
            .import_runtime_replay_source(
                &runtime_authority,
                expected.expectation_id(),
                &source,
                &fence,
                now_ms()?,
            )
            .is_err());
        assert!(source
            .load_legacy_replay_source_seal(&source_binding(&expected)?)?
            .is_none());
        assert_eq!(raw_snapshot(&raw_source)?, changed);
        assert_eq!(
            store.load_runtime_replay_migration(&runtime_authority, &fence, now_ms()?)?,
            Some(expected.clone()),
        );
        assert_destination_history(&Connection::open(&database)?, &expected)?;
    }
    Ok(())
}
