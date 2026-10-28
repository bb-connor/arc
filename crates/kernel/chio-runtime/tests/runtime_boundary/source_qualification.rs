#![cfg(unix)]

use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, RuntimeSourcePort,
};
use chio_runtime::SqliteRuntimeOrchestrationStore;

#[test]
fn facade_qualification_preserves_live_source_binding() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite3");
    let source = SqliteRuntimeOrchestrationStore::open(&path)?;
    let core = chio_runtime_core::SqliteRuntimeOrchestrationStore::open(&path)?;
    let qualification = source.qualify(
        &AdmissionIdentifier::try_new("source", "source")?,
        &AdmissionIdentifier::try_new("runtime", "runtime")?,
        &AdmissionIdentifier::try_new("destination", "destination")?,
    )?;
    source.verify_exact(&qualification)?;
    core.verify_exact(&qualification)?;
    let other = SqliteRuntimeOrchestrationStore::open(directory.path().join("other.sqlite3"))?;
    assert_eq!(other.verify_exact(&qualification), Err(AdmissionOperationStoreError::Invariant(
        "runtime admission rejected: runtime_source_qualification_invalid: runtime source qualification is missing".into(),
    )));
    Ok(())
}
