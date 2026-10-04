use super::*;

#[test]
fn instrumentation_preserves_atomic_trust_floor_transitions() -> Result<(), BoxError> {
    let store = TimingAdmissionStore::new(
        Arc::new(AdmissionBackend::Memory(
            InMemoryRuntimeAdmissionStore::new(),
        )),
        Arc::new(PhaseLedger::default()),
    );
    let first = RuntimeTrustFloorEntry {
        verifier_id: "origin".into(),
        key_id: "key".into(),
        highest_version: 1,
        latest_bundle_sha256: "a".repeat(64),
        latest_revocation_checkpoint_sha256: "b".repeat(64),
    };
    store.validate_and_record_runtime_trust_floor(first.clone(), None)?;
    let next = RuntimeTrustFloorEntry {
        highest_version: 2,
        latest_bundle_sha256: "c".repeat(64),
        ..first.clone()
    };
    assert!(store
        .validate_and_record_runtime_trust_floor(next.clone(), Some(&"d".repeat(64)))
        .is_err());
    assert_eq!(
        store.runtime_trust_floor("origin", "key")?,
        Some(first.clone())
    );
    store
        .validate_and_record_runtime_trust_floor(next.clone(), Some(&first.latest_bundle_sha256))?;
    assert_eq!(store.runtime_trust_floor("origin", "key")?, Some(next));
    Ok(())
}
