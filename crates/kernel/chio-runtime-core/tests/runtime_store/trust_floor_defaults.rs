use super::*;
use chio_runtime_core::{LayeredRuntimeAdmissionStore, RuntimeTrustFloorStore};

fn entry() -> RuntimeTrustFloorEntry {
    RuntimeTrustFloorEntry {
        verifier_id: "verifier-default-test".into(),
        key_id: "key-default-test".into(),
        highest_version: 1,
        latest_bundle_sha256: "a".repeat(64),
        latest_revocation_checkpoint_sha256: "b".repeat(64),
    }
}

fn assert_unsupported(result: Result<(), ChioRuntimeError>) {
    match result {
        Err(error) => assert_rejected_code(error, "runtime_trust_floor_store_unsupported"),
        Ok(()) => panic!("a read/write fallback must never admit a trust-floor transition"),
    }
}

#[test]
fn admission_default_and_blanket_floor_adapter_fail_closed_without_writing(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = StoreWithoutTreatyContinuationSupport::default();
    assert_unsupported(
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(&store, entry(), None),
    );
    assert_unsupported(
        RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(&store, entry(), None),
    );
    assert_eq!(
        store
            .floor_callbacks
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
    );
    assert!(RuntimeAdmissionStore::runtime_trust_floor(
        &store.inner,
        &entry().verifier_id,
        &entry().key_id,
    )?
    .is_none());
    Ok(())
}

struct ReadWriteOnlyFloor;

impl RuntimeTrustFloorStore for ReadWriteOnlyFloor {
    fn runtime_trust_floor(
        &self,
        _verifier_id: &str,
        _key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        panic!("unsupported atomic floor operation must not read the floor")
    }

    fn record_runtime_trust_floor(
        &self,
        _entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        panic!("unsupported atomic floor operation must not write the floor")
    }
}

#[test]
fn floor_default_and_layered_adapter_never_fall_back_to_separate_callbacks() {
    let floor_store = ReadWriteOnlyFloor;
    assert_unsupported(floor_store.validate_and_record_runtime_trust_floor(entry(), None));
    let admission_store = InMemoryRuntimeAdmissionStore::new();
    let layered = LayeredRuntimeAdmissionStore::new(&admission_store, &floor_store);
    assert_unsupported(
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(&layered, entry(), None),
    );
}
