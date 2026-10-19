use std::path::Path;

use chio_core_types::canonical::UntrustedJsonError;
use chio_runtime_core::{
    ChioRuntimeError, JsonRuntimeAdmissionStore, JsonRuntimeTrustFloorStateStore,
    RuntimeTrustFloorEntry, RuntimeTrustFloorStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OVERSIZED_ID_BYTES: usize = 64 * 1024 * 1024;
const JSON_STORE_LIMIT: usize = 64 * 1024 * 1024;

fn floor(verifier_id: String) -> RuntimeTrustFloorEntry {
    RuntimeTrustFloorEntry {
        verifier_id,
        key_id: "key-json-store-bound".to_owned(),
        highest_version: 1,
        latest_bundle_sha256: "1".repeat(64),
        latest_revocation_checkpoint_sha256: "2".repeat(64),
    }
}

fn assert_oversized_write_preserves_store<S: RuntimeTrustFloorStore>(
    open: impl Fn(&Path) -> Result<S, ChioRuntimeError>,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.json");
    let kept = floor("verifier-kept".to_owned());
    let store = open(&path)?;
    store.record_runtime_trust_floor(kept.clone())?;
    let persisted = std::fs::read(&path)?;

    let oversized = floor("v".repeat(OVERSIZED_ID_BYTES));
    match store.record_runtime_trust_floor(oversized.clone()) {
        Err(ChioRuntimeError::Rejected { code, .. }) => {
            assert_eq!(code, "runtime_json_store_too_large")
        }
        other => panic!("expected runtime_json_store_too_large, got {other:?}"),
    }

    assert_eq!(std::fs::read(&path)?, persisted);
    assert_eq!(
        store.runtime_trust_floor(&oversized.verifier_id, &oversized.key_id)?,
        None
    );
    assert_eq!(
        store.runtime_trust_floor(&kept.verifier_id, &kept.key_id)?,
        Some(kept.clone())
    );
    let reopened = open(&path)?;
    assert_eq!(
        reopened.runtime_trust_floor(&kept.verifier_id, &kept.key_id)?,
        Some(kept)
    );
    Ok(())
}

#[test]
fn json_admission_store_refuses_oversized_write_and_keeps_state() -> TestResult {
    assert_oversized_write_preserves_store(|path| JsonRuntimeAdmissionStore::open(path))
}

#[test]
fn json_trust_floor_store_refuses_oversized_write_and_keeps_state() -> TestResult {
    assert_oversized_write_preserves_store(|path| JsonRuntimeTrustFloorStateStore::open(path))
}

fn assert_oversized_file_refused_on_open<S>(
    open: impl Fn(&Path) -> Result<S, ChioRuntimeError>,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.json");
    std::fs::File::create(&path)?.set_len(u64::try_from(JSON_STORE_LIMIT)? + 1)?;

    match open(&path) {
        Err(ChioRuntimeError::UntrustedInput(UntrustedJsonError::TooLarge { bytes, bound })) => {
            assert_eq!(bytes, JSON_STORE_LIMIT + 1);
            assert_eq!(bound, JSON_STORE_LIMIT);
        }
        Err(other) => panic!("expected oversized store refusal, got {other:?}"),
        Ok(_) => panic!("expected oversized store refusal, store opened"),
    }
    Ok(())
}

#[test]
fn json_admission_store_refuses_oversized_file_on_open() -> TestResult {
    assert_oversized_file_refused_on_open(|path| JsonRuntimeAdmissionStore::open(path))
}

#[test]
fn json_trust_floor_store_refuses_oversized_file_on_open() -> TestResult {
    assert_oversized_file_refused_on_open(|path| JsonRuntimeTrustFloorStateStore::open(path))
}
