use super::*;
use chio_runtime_core::{runtime_admission_bundle_from_json, runtime_admission_bundle_sha256};
use std::error::Error;

#[test]
fn original_runtime_json_rejects_ambiguity_with_private_cause() -> Result<(), Box<dyn Error>> {
    let original = bundle();
    let wire = serde_json::to_string(&original)?;
    assert_eq!(
        runtime_admission_bundle_from_json(&wire)?.admission_id,
        original.admission_id
    );
    let mut duplicate = wire.clone();
    let (key, value) = serde_json::to_value(&original)?
        .as_object()
        .ok_or("object")?
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .ok_or("field")?;
    duplicate.insert_str(1, &format!("{}:{},", serde_json::to_string(&key)?, value));
    let error = runtime_admission_bundle_from_json(&duplicate)
        .err()
        .ok_or("accepted duplicate key")?;
    assert_eq!(
        error.code(),
        "urn:chio:error:attest:signed-json-invalid-input"
    );
    assert!(error.source().and_then(Error::source).is_some());
    assert!(!format!("{error:?}").contains(&original.admission_id));
    Ok(())
}

#[test]
fn sqlite_bundle_readback_binds_digest_and_index_across_restart() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("binding.sqlite3");
    let original = bundle();
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.insert_bundle(original.clone())?;
    assert_eq!(
        store
            .bundle(&original.admission_id)?
            .ok_or("missing bundle")?
            .admission_id,
        original.admission_id
    );
    let connection = rusqlite::Connection::open(&path)?;
    let mut substituted = original.clone();
    substituted.admission_id = "valid-but-different-admission".to_owned();
    // Even an internally consistent replacement must match the requested key.
    connection.execute(
        "UPDATE runtime_admission_bundles SET bundle_sha256=?1, raw_json=?2 WHERE admission_id=?3",
        rusqlite::params![
            runtime_admission_bundle_sha256(&substituted)?,
            serde_json::to_string(&substituted)?,
            original.admission_id
        ],
    )?;
    drop(store);
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let error = store
        .bundle(&original.admission_id)
        .err()
        .ok_or("accepted substituted bundle")?;
    assert_eq!(error.code(), "runtime_stored_bundle_binding_mismatch");
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM runtime_admission_bundles",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    // Restore the identity alone: the retained digest must still be checked.
    connection.execute(
        "UPDATE runtime_admission_bundles SET raw_json=?1",
        [serde_json::to_string(&original)?],
    )?;
    assert_eq!(
        store
            .bundle(&original.admission_id)
            .err()
            .ok_or("accepted wrong digest")?
            .code(),
        "runtime_stored_bundle_binding_mismatch"
    );
    connection.execute(
        "UPDATE runtime_admission_bundles SET bundle_sha256=?1",
        [runtime_admission_bundle_sha256(&original)?],
    )?;
    assert_eq!(
        store
            .bundle(&original.admission_id)?
            .ok_or("missing repaired bundle")?
            .admission_id,
        original.admission_id
    );
    Ok(())
}

#[test]
fn sqlite_swarm_and_treaty_readback_rejects_substitution() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("artifacts.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let original = swarm_authority_bundle_fixture()?;
    store.insert_swarm_authority_bundle(original.clone())?;
    assert_eq!(
        store
            .swarm_authority_bundle(&original.task_graph.graph_id)?
            .ok_or("missing swarm")?
            .task_graph
            .graph_id,
        original.task_graph.graph_id
    );
    let connection = rusqlite::Connection::open(&path)?;
    let mut replacement = original.clone();
    replacement.task_graph.graph_id = "other-valid-graph".into();
    let digest =
        chio_core_types::hashing::sha256_hex(&chio_core_types::canonical_json_bytes(&replacement)?);
    connection.execute(
        "UPDATE runtime_swarm_authority_bundles SET raw_json=?1, bundle_sha256=?2",
        rusqlite::params![serde_json::to_string(&replacement)?, digest],
    )?;
    assert_eq!(
        store
            .swarm_authority_bundle(&original.task_graph.graph_id)
            .err()
            .ok_or("accepted wrong graph")?
            .code(),
        "runtime_stored_bundle_binding_mismatch"
    );
    store.insert_treaty_runtime_artifact(
        "scope",
        "scope-1",
        &serde_json::json!({"scope":"original"}),
    )?;
    let artifact = store
        .treaty_runtime_artifact("scope", "scope-1")?
        .ok_or("missing artifact")?;
    assert_eq!(artifact.raw_json["scope"], "original");
    connection.execute(
        "UPDATE runtime_treaty_artifacts SET raw_json=?1",
        [r#"{"scope":"substituted"}"#],
    )?;
    drop(store);
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_eq!(
        store
            .treaty_runtime_artifact("scope", "scope-1")
            .err()
            .ok_or("accepted wrong artifact")?
            .code(),
        "runtime_stored_artifact_binding_mismatch"
    );
    Ok(())
}

#[test]
fn runtime_clock_fault_refuses_swarm_write_without_a_partial_row() -> Result<(), Box<dyn Error>> {
    use chio_security_types::clock::{Clock, ClockError, ClockReading};
    struct BrokenClock;
    impl Clock for BrokenClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            Err(ClockError::BeforeEpoch)
        }
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("clock.sqlite3");
    let store =
        SqliteRuntimeOrchestrationStore::open_with_clock(&path, std::sync::Arc::new(BrokenClock))?;
    let bundle = swarm_authority_bundle_fixture()?;
    let error = store
        .insert_swarm_authority_bundle(bundle.clone())
        .err()
        .ok_or("accepted broken clock")?;
    assert_eq!(error.code(), ClockError::BeforeEpoch.code());
    assert!(error
        .source()
        .and_then(|source| source.downcast_ref::<ClockError>())
        .is_some());
    assert_eq!(
        store.swarm_authority_bundle(&bundle.task_graph.graph_id)?,
        None
    );
    drop(store);
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(
        &path,
        std::sync::Arc::new(chio_security_types::clock::FixedClock::from_millis(
            1_800_000_000_000,
        )),
    )?;
    store.insert_swarm_authority_bundle(bundle.clone())?;
    assert_eq!(
        store
            .swarm_authority_bundle(&bundle.task_graph.graph_id)?
            .ok_or("missing accepted bundle")?
            .task_graph
            .graph_id,
        bundle.task_graph.graph_id
    );
    Ok(())
}
