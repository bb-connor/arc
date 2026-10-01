use chio_runtime_core::{
    ChioRuntimeError, RuntimeAdmissionStore, RuntimeReplayMarkerKind, RuntimeReplaySourceBinding,
    RuntimeReplaySourceSeal, SqliteRuntimeOrchestrationStore,
};
use rusqlite::{params, Connection};

#[path = "replay_source/barrier.rs"]
mod barrier;
#[path = "replay_source/bounds.rs"]
mod bounds;
#[path = "replay_source/crash.rs"]
mod crash;
#[path = "replay_source/destination.rs"]
mod destination;
#[path = "replay_source/expectation.rs"]
mod expectation;
#[path = "replay_source/identity.rs"]
mod identity;
#[path = "replay_source/integrity.rs"]
mod integrity;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TABLES: [(&str, &str, &str); 3] = [
    ("runtime_consumed_leases", "lease_id", "lease"),
    (
        "runtime_consumed_treaty_continuations",
        "continuation_id",
        "treaty",
    ),
    (
        "runtime_consumed_swarm_continuations",
        "continuation_id",
        "swarm",
    ),
];

fn binding() -> TestResult<RuntimeReplaySourceBinding> {
    Ok(RuntimeReplaySourceBinding::new(
        "replay-source-tests".to_owned(),
        "runtime-authority-tests".to_owned(),
        "admission-authority-tests".to_owned(),
    )?)
}

fn assert_code<T: std::fmt::Debug>(result: Result<T, ChioRuntimeError>, expected: &str) {
    match result {
        Err(error) => assert_eq!(error.code(), expected, "{error:?}"),
        Ok(value) => panic!("expected {expected}, got {value:?}"),
    }
}

fn seed_inventory(store: &SqliteRuntimeOrchestrationStore) -> TestResult {
    // Reversed insertion order and shared IDs across kinds exercise canonical
    // ordering without conflating the three independent legacy resources.
    for resource_id in ["resource-z", "resource-a"] {
        store.consume_swarm_continuation(resource_id, "admission-swarm")?;
        store.consume_treaty_continuation(resource_id, "admission-treaty")?;
        store.consume_destructive_lease(resource_id, "admission-lease")?;
    }
    Ok(())
}

fn assert_inventory(seal: &RuntimeReplaySourceSeal) {
    assert_eq!(seal.markers().len(), 6);
    for (kind, admission_id) in [
        (RuntimeReplayMarkerKind::DestructiveLease, "admission-lease"),
        (
            RuntimeReplayMarkerKind::TreatyContinuation,
            "admission-treaty",
        ),
        (
            RuntimeReplayMarkerKind::SwarmContinuation,
            "admission-swarm",
        ),
    ] {
        for resource_id in ["resource-a", "resource-z"] {
            assert_eq!(
                seal.markers()
                    .iter()
                    .filter(|marker| {
                        marker.kind() == kind
                            && marker.resource_id() == resource_id
                            && marker.admission_id() == admission_id
                    })
                    .count(),
                1,
                "the seal must retain every original marker and owner"
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RawSnapshot {
    schema: Vec<(String, String, Option<String>)>,
    rows: Vec<(String, String, String)>,
}

fn raw_snapshot(connection: &Connection) -> TestResult<RawSnapshot> {
    let schema = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema WHERE name LIKE 'runtime_%' ORDER BY type, name",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut rows = Vec::new();
    for (table, key, _) in
        TABLES
            .into_iter()
            .chain([("runtime_replay_source_seal", "singleton", "seal")])
    {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            continue;
        }
        let value = if table == "runtime_replay_source_seal" {
            "canonical_bytes"
        } else {
            "admission_id"
        };
        let sql = format!("SELECT quote({key}), quote({value}) FROM {table} ORDER BY {key}");
        for row in connection
            .prepare(&sql)?
            .query_map([], |row| Ok((table.to_owned(), row.get(0)?, row.get(1)?)))?
        {
            rows.push(row?);
        }
    }
    Ok(RawSnapshot { schema, rows })
}

#[test]
fn complete_inventory_reseals_and_reopens_exactly() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("complete.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = binding()?;
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
    seed_inventory(&store)?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    assert_eq!(seal.binding(), &binding);
    assert_inventory(&seal);
    assert_eq!(seal.inventory_sha256().len(), 64);
    store.verify_legacy_replay_source_seal(&seal)?;
    let canonical = seal.canonical_bytes()?;
    assert_eq!(
        store
            .seal_legacy_replay_source(&binding)?
            .canonical_bytes()?,
        canonical
    );
    drop(store);

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let loaded = reopened
        .load_legacy_replay_source_seal(&binding)?
        .ok_or("retained seal disappeared on reopen")?;
    assert_eq!(loaded.canonical_bytes()?, canonical);
    assert_eq!(loaded.file_identity(), seal.file_identity());
    assert_inventory(&loaded);
    reopened.verify_legacy_replay_source_seal(&seal)?;
    assert_eq!(
        reopened
            .seal_legacy_replay_source(&binding)?
            .canonical_bytes()?,
        canonical
    );
    Ok(())
}

#[test]
fn empty_inventory_is_sealed_and_cannot_accept_a_later_legacy_marker() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("empty.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = binding()?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    assert!(seal.markers().is_empty());
    assert_eq!(seal.inventory_sha256().len(), 64);
    assert_code(
        store.consume_destructive_lease("late-lease", "late-admission"),
        "runtime_replay_source_sealed",
    );
    assert_eq!(
        store
            .seal_legacy_replay_source(&binding)?
            .canonical_bytes()?,
        seal.canonical_bytes()?
    );
    drop(store);
    let reopened = SqliteRuntimeOrchestrationStore::open(path)?;
    reopened.verify_legacy_replay_source_seal(&seal)?;
    assert_eq!(
        reopened
            .load_legacy_replay_source_seal(&binding)?
            .ok_or("empty seal disappeared")?
            .canonical_bytes()?,
        seal.canonical_bytes()?
    );
    Ok(())
}

#[test]
fn every_binding_component_is_checked_without_rebinding_the_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("binding.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let binding = binding()?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    let connection = Connection::open(&path)?;
    let before = raw_snapshot(&connection)?;
    for (source, runtime, destination) in [
        (
            "wrong-source",
            "runtime-authority-tests",
            "admission-authority-tests",
        ),
        (
            "replay-source-tests",
            "wrong-runtime",
            "admission-authority-tests",
        ),
        (
            "replay-source-tests",
            "runtime-authority-tests",
            "wrong-destination",
        ),
    ] {
        let mismatched = RuntimeReplaySourceBinding::new(
            source.to_owned(),
            runtime.to_owned(),
            destination.to_owned(),
        )?;
        assert_code(
            store.load_legacy_replay_source_seal(&mismatched),
            "runtime_replay_source_invalid",
        );
        assert_code(
            store.seal_legacy_replay_source(&mismatched),
            "runtime_replay_source_invalid",
        );
        assert_eq!(raw_snapshot(&connection)?, before);
        store.verify_legacy_replay_source_seal(&seal)?;
    }
    Ok(())
}

#[test]
fn canonical_inventory_order_is_stable_but_each_seal_binds_its_physical_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let first = SqliteRuntimeOrchestrationStore::open(directory.path().join("first.sqlite3"))?;
    let second = SqliteRuntimeOrchestrationStore::open(directory.path().join("second.sqlite3"))?;
    let changed = SqliteRuntimeOrchestrationStore::open(directory.path().join("changed.sqlite3"))?;
    seed_inventory(&first)?;
    for resource_id in ["resource-a", "resource-z"] {
        second.consume_destructive_lease(resource_id, "admission-lease")?;
        second.consume_treaty_continuation(resource_id, "admission-treaty")?;
        second.consume_swarm_continuation(resource_id, "admission-swarm")?;
    }
    seed_inventory(&changed)?;
    changed.release_destructive_lease("resource-a", "admission-lease")?;
    changed.consume_destructive_lease("resource-a", "different-admission")?;
    let binding = binding()?;
    let first_seal = first.seal_legacy_replay_source(&binding)?;
    let second_seal = second.seal_legacy_replay_source(&binding)?;
    let changed_seal = changed.seal_legacy_replay_source(&binding)?;
    assert_eq!(first_seal.markers(), second_seal.markers());
    assert_ne!(first_seal.markers(), changed_seal.markers());
    assert_ne!(
        first_seal.inventory_sha256(),
        second_seal.inventory_sha256()
    );
    assert_ne!(first_seal.file_identity(), second_seal.file_identity());
    assert_code(
        second.verify_legacy_replay_source_seal(&first_seal),
        "runtime_replay_source_invalid",
    );
    Ok(())
}
