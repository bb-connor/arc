#[cfg(unix)]
use chio_runtime::RuntimeReplayMarkerKind;
use chio_runtime::{
    ChioRuntimeAdmissionStore, RuntimeReplaySourceBinding, SqliteRuntimeOrchestrationStore,
};

#[cfg(unix)]
fn persisted_source_bytes(
    path: &std::path::Path,
) -> Result<(Vec<u8>, Option<Vec<u8>>), std::io::Error> {
    let mut wal_path = path.as_os_str().to_owned();
    wal_path.push("-wal");
    let wal = match std::fs::read(std::path::PathBuf::from(wal_path)) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    // SHM read marks are mutable even for readers. The main file and WAL are
    // the persisted SQLite data checked here, with all handles kept open.
    Ok((std::fs::read(path)?, wal))
}

#[cfg(unix)]
#[test]
fn facade_source_port_preserves_exact_preview_seal_verify_and_rejection_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::admission_operation::{
        AdmissionIdentifier, AdmissionOperationStoreError, RuntimeReplaySourcePort,
    };

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("facade-source.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let core_store = chio_runtime_core::SqliteRuntimeOrchestrationStore::open(&path)?;
    let other =
        SqliteRuntimeOrchestrationStore::open(directory.path().join("other-source.sqlite3"))?;
    for source in [&store, &other] {
        source.consume_destructive_lease("lease", "historical-lease")?;
        source.consume_treaty_continuation("treaty", "historical-treaty")?;
        source.consume_swarm_continuation("swarm", "historical-swarm")?;
    }
    let facade: &dyn RuntimeReplaySourcePort = &store;
    let core: &dyn RuntimeReplaySourcePort = &core_store;
    let other_port: &dyn RuntimeReplaySourcePort = &other;
    let source_id = AdmissionIdentifier::try_new("source_id", "source")?;
    let runtime = AdmissionIdentifier::try_new("runtime_authority_id", "runtime")?;
    let destination = AdmissionIdentifier::try_new("destination_authority_id", "destination")?;
    let binding = RuntimeReplaySourceBinding::new("source", "runtime", "destination")?;
    let before = persisted_source_bytes(&path)?;
    let expected = facade.preview(&source_id, &runtime, &destination)?;
    assert!(store
        .verify_operation_owned_replay_source(&expected)
        .is_err());
    assert_eq!(expected, core.preview(&source_id, &runtime, &destination)?);
    assert_eq!(expected.markers().len(), 3);
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
    let unsealed_error = facade
        .verify_exact(&expected)
        .err()
        .ok_or("preview was treated as a seal")?;
    assert_eq!(
        unsealed_error,
        core.verify_exact(&expected)
            .err()
            .ok_or("core accepted an unsealed preview")?
    );
    assert_eq!(
        persisted_source_bytes(&path)?,
        before,
        "preview and verification must not write"
    );

    let wrong = other_port.preview(&source_id, &runtime, &destination)?;
    assert_ne!(
        (wrong.device(), wrong.inode()),
        (expected.device(), expected.inode())
    );
    let facade_error = facade
        .seal_exact(&wrong)
        .err()
        .ok_or("facade sealed the wrong source")?;
    let core_error = core
        .seal_exact(&wrong)
        .err()
        .ok_or("core sealed the wrong source")?;
    assert!(matches!(
        facade_error,
        AdmissionOperationStoreError::Invariant(_)
    ));
    assert_eq!(
        facade_error, core_error,
        "the trait adapter must preserve the core error exactly"
    );
    assert_eq!(
        store
            .seal_expected_legacy_replay_source(&wrong)
            .err()
            .ok_or("inherent facade accepted wrong source")?
            .code(),
        "runtime_replay_source_invalid",
    );
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
    assert_eq!(
        persisted_source_bytes(&path)?,
        before,
        "wrong source rejection must not write"
    );

    facade.seal_exact(&expected)?;
    facade.verify_exact(&expected)?;
    core.verify_exact(&expected)?;
    store.verify_operation_owned_replay_source(&expected)?;
    assert!(other
        .verify_operation_owned_replay_source(&expected)
        .is_err());
    let seal = store
        .load_legacy_replay_source_seal(&binding)?
        .ok_or("facade seal was not retained")?;
    assert_eq!(
        seal.canonical_bytes()?.as_slice(),
        expected.canonical_bytes()
    );
    let sealed_bytes = persisted_source_bytes(&path)?;
    facade.seal_exact(&expected)?;
    assert_eq!(
        facade
            .preview(&source_id, &runtime, &destination)
            .err()
            .ok_or("facade previewed a sealed source")?,
        core.preview(&source_id, &runtime, &destination)
            .err()
            .ok_or("core previewed a sealed source")?,
    );
    assert_eq!(
        facade
            .verify_exact(&wrong)
            .err()
            .ok_or("facade verified the wrong source")?,
        core.verify_exact(&wrong)
            .err()
            .ok_or("core verified the wrong source")?,
    );
    assert_eq!(persisted_source_bytes(&path)?, sealed_bytes);
    Ok(())
}

#[cfg(unix)]
#[test]
fn facade_seal_preserves_markers_and_propagates_fail_closed_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = RuntimeReplaySourceBinding::new("source", "runtime", "destination")?;
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
    store.consume_destructive_lease("lease", "admission")?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    assert_eq!(seal.markers().len(), 1);
    assert_eq!(
        seal.markers()[0].kind(),
        RuntimeReplayMarkerKind::DestructiveLease
    );
    assert_eq!(seal.markers()[0].resource_id(), "lease");
    assert_eq!(seal.markers()[0].admission_id(), "admission");
    store.verify_legacy_replay_source_seal(&seal)?;
    assert_eq!(store.seal_legacy_replay_source(&binding)?, seal);
    for result in [
        store.consume_destructive_lease("new-lease", "admission"),
        store.release_destructive_lease("lease", "admission"),
        store.consume_treaty_continuation("new-treaty", "admission"),
        store.release_treaty_continuation("treaty", "admission"),
        store.consume_swarm_continuation("new-swarm", "admission"),
        store.release_swarm_continuation("swarm", "admission"),
    ] {
        let Err(error) = result else {
            return Err("facade permitted a sealed replay mutation".into());
        };
        assert_eq!(error.code(), "runtime_replay_source_sealed");
    }
    let wrong = RuntimeReplaySourceBinding::new("source", "runtime", "another-destination")?;
    let Err(error) = store.seal_legacy_replay_source(&wrong) else {
        return Err("facade replaced a sealed destination binding".into());
    };
    assert_eq!(error.code(), "runtime_replay_source_invalid");
    drop(store);
    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_eq!(
        reopened.load_legacy_replay_source_seal(&binding)?,
        Some(seal.clone())
    );
    reopened.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn facade_propagates_unsupported_sealing_without_retiring_legacy_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unsupported-runtime.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = RuntimeReplaySourceBinding::new("source", "runtime", "destination")?;
    store.consume_destructive_lease("lease", "admission")?;
    store.consume_treaty_continuation("treaty", "admission")?;
    store.consume_swarm_continuation("swarm", "admission")?;
    let error = store
        .seal_legacy_replay_source(&binding)
        .err()
        .ok_or("facade unexpectedly sealed a source on an unsupported platform")?;
    assert_eq!(error.code(), "runtime_replay_source_invalid");
    assert!(error.to_string().contains("requires Unix"));
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
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
