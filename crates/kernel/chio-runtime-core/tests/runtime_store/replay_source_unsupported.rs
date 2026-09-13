use chio_kernel::admission_operation::{AdmissionIdentifier, RuntimeReplaySourcePort};
use chio_runtime_core::{
    RuntimeAdmissionStore, RuntimeReplaySourceBinding, SqliteRuntimeOrchestrationStore,
};

#[test]
fn unsupported_platform_rejects_sealing_without_retiring_legacy_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unsupported-seal.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = RuntimeReplaySourceBinding::new("source", "runtime", "destination")?;
    store.consume_destructive_lease("lease", "admission")?;
    store.consume_treaty_continuation("treaty", "admission")?;
    store.consume_swarm_continuation("swarm", "admission")?;
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());

    let preview_error = store
        .preview_legacy_replay_source(&binding)
        .err()
        .ok_or("unsupported platform unexpectedly previewed a source identity")?;
    assert_eq!(preview_error.code(), "runtime_replay_source_invalid");
    assert!(preview_error.to_string().contains("requires Unix"));
    let port: &dyn RuntimeReplaySourcePort = &store;
    assert!(port
        .preview(
            &AdmissionIdentifier::try_new("source_id", "source")?,
            &AdmissionIdentifier::try_new("runtime_authority_id", "runtime")?,
            &AdmissionIdentifier::try_new("destination_authority_id", "destination")?,
        )
        .is_err());

    let error = store
        .seal_legacy_replay_source(&binding)
        .err()
        .ok_or("unsupported platform unexpectedly sealed a replay source")?;
    assert_eq!(error.code(), "runtime_replay_source_invalid");
    assert!(error.to_string().contains("requires Unix"));
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());

    let raw = rusqlite::Connection::open(&path)?;
    let seal_objects: i64 = raw.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE lower(name) GLOB '*runtime_replay_source*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        seal_objects, 0,
        "unsupported sealing must install no barriers"
    );
    for (table, key, resource) in [
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
    ] {
        let owner: String = raw.query_row(
            &format!("SELECT admission_id FROM {table} WHERE {key} = ?1"),
            [resource],
            |row| row.get(0),
        )?;
        assert_eq!(owner, "admission");
    }
    drop(raw);
    drop(store);

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert!(reopened.load_legacy_replay_source_seal(&binding)?.is_none());
    reopened.release_destructive_lease("lease", "admission")?;
    reopened.release_treaty_continuation("treaty", "admission")?;
    reopened.release_swarm_continuation("swarm", "admission")?;
    reopened.consume_destructive_lease("lease", "next-admission")?;
    reopened.consume_treaty_continuation("treaty", "next-admission")?;
    reopened.consume_swarm_continuation("swarm", "next-admission")?;
    Ok(())
}
