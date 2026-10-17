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
fn sqlite_treaty_readback_rejects_substitution() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("artifacts.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
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
