use chio_core_types::crypto::Keypair;
use chio_runtime_core::{
    ChioRuntimeError, InMemoryRuntimeAdmissionStore, RuntimeAdmissionBundle, RuntimeAdmissionStore,
    RuntimeEvidenceManifestEntry, RuntimeOrchestrationProfile, RuntimeRequestBinding,
    RuntimeTrustFloorEntry, SqliteRuntimeOrchestrationStore, TreatyScope,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA,
    CHIO_TREATY_SCOPE_SCHEMA,
};

#[path = "runtime_store/evidence_artifacts_schema.rs"]
mod evidence_artifacts_schema;
#[path = "runtime_store/json_store_bounds.rs"]
mod json_store_bounds;
#[path = "runtime_store/trust_floor_defaults.rs"]
mod trust_floor_defaults;
#[path = "runtime_store/trust_floor_races.rs"]
mod trust_floor_races;

#[derive(Default)]
struct ReadWriteOnlyStore {
    inner: InMemoryRuntimeAdmissionStore,
    floor_callbacks: std::sync::atomic::AtomicUsize,
}

impl RuntimeAdmissionStore for ReadWriteOnlyStore {
    fn commit_runtime_admission_authority(
        &self,
        _: &chio_runtime_core::RuntimeAdmissionAuthorityCommit,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Rejected {
            code: "treaty_epoch_unavailable",
            detail: "runtime backend does not support atomic treaty authority".into(),
        })
    }

    fn verify_retained_runtime_treaty_authorization(
        &self,
        _: &chio_runtime_core::RuntimeTreatyAuthorizationBinding,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Rejected {
            code: "treaty_epoch_unavailable",
            detail: "runtime backend does not support retained treaty authorization".into(),
        })
    }

    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.inner.bundle(admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.floor_callbacks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.floor_callbacks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.record_runtime_trust_floor(entry)
    }
}

#[test]
fn unqualified_store_refuses_operation_owned_source() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::admission_operation::{AdmissionIdentifier, RuntimeSourceQualificationV1};
    let source = RuntimeSourceQualificationV1::new(
        AdmissionIdentifier::try_new("source_id", "source")?,
        AdmissionIdentifier::try_new("runtime_id", "runtime")?,
        AdmissionIdentifier::try_new("destination_id", "destination")?,
        1,
        2,
        1,
    )?;
    let store = ReadWriteOnlyStore::default();
    match store.verify_operation_owned_runtime_source(&source) {
        Ok(()) => panic!("unqualified backend accepted a source descriptor"),
        Err(error) => assert_rejected_code(error, "operation_owned_runtime_source_unsupported"),
    }
    Ok(())
}

fn assert_rejected_code(error: ChioRuntimeError, expected: &'static str) {
    match error {
        ChioRuntimeError::Rejected { code, .. } => assert_eq!(code, expected),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

#[test]
fn in_memory_runtime_admission_store_insert_bundle_is_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let original = bundle();
    store.insert_bundle(original.clone())?;
    store.insert_bundle(original)?;

    let mut conflicting = bundle();
    conflicting.workflow_id = "wf-conflict".to_string();
    match store.insert_bundle(conflicting) {
        Ok(()) => Err("conflicting bundle insert unexpectedly succeeded".into()),
        Err(error) => {
            assert_eq!(error.code(), "duplicate_admission_bundle");
            Ok(())
        }
    }
}

#[test]
fn sqlite_runtime_orchestration_store_persists_run_and_step_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-orchestration.sqlite3");
    {
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        store.insert_bundle(bundle())?;
        store.register_run("runtime-orchestration-1")?;
        let lease =
            store.acquire_current_run_lease("runtime-orchestration-1", "fixture", 60_000)?;
        store.record_run_state(&lease, "proof_accepted", None)?;
        store.record_step_state(
            &lease,
            chio_runtime_core::RuntimeOrchestrationStepState {
                step_index: 1,
                admission_id: "adm-live-1".to_string(),
                state: "proof_accepted".to_string(),
                destructive: true,
                tool_receipt_sha256: Some("2".repeat(64)),
                lease_id: Some("lease-live-1".to_string()),
            },
        )?;
    }

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let profile = RuntimeOrchestrationProfile {
        schema: CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-runtime-orchestration".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        mode: "enforce".to_string(),
        max_concurrent_runs: 2,
        fail_closed_on: vec!["evidence_hash_mismatch".to_string()],
    };
    let profile_sha256 = chio_runtime_core::runtime_orchestration_profile_sha256(&profile)?;
    let status = reopened.status_report(&profile, profile_sha256, 1_800_000_002_000, true)?;
    assert_eq!(status.store_backend, "sqlite");
    assert_eq!(status.run_counts.get("proof_accepted"), Some(&1));
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_persists_treaty_evidence_idempotently(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-treaty.sqlite3");
    let treaty = treaty_scope();
    let treaty_sha256 = chio_runtime_core::treaty_scope_sha256(&treaty)?;

    {
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &treaty)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &treaty)?;

        let mut mismatched = treaty.clone();
        mismatched.expires_at_unix_ms += 1;
        let duplicate =
            store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &mismatched);
        match duplicate {
            Ok(()) => panic!("expected treaty evidence id mismatch rejection"),
            Err(error) => assert_eq!(error.code(), "duplicate_treaty_runtime_artifact_mismatch"),
        }
    }

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let record = reopened
        .treaty_runtime_artifact("treaty_scope", &treaty.treaty_id)?
        .ok_or_else(|| std::io::Error::other("treaty evidence missing after restart"))?;
    assert_eq!(record.evidence_kind, "treaty_scope");
    assert_eq!(record.evidence_id, treaty.treaty_id);
    assert_eq!(record.artifact_sha256, treaty_sha256);
    assert_eq!(
        serde_json::from_value::<TreatyScope>(record.raw_json)?,
        treaty
    );
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_preserves_same_artifact_hash_per_run(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-artifacts.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let entry = RuntimeEvidenceManifestEntry {
        role: "proof_package".to_string(),
        path: "proof-package.json".to_string(),
        sha256: "7".repeat(64),
        byte_count: 4096,
    };

    for run in ["runtime-run-a", "runtime-run-b"] {
        store.register_run(run)?;
        let lease = store.acquire_current_run_lease(run, "fixture", 60_000)?;
        store.record_evidence_artifact(&lease, &entry)?;
    }

    let connection = rusqlite::Connection::open(&path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_evidence_artifacts WHERE artifact_sha256 = ?1",
        rusqlite::params![entry.sha256],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}

fn binding() -> RuntimeRequestBinding {
    RuntimeRequestBinding {
        request_id: "req-live-destructive".to_string(),
        capability_id: "cap-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        tool_args_sha256: "a".repeat(64),
        origin_kernel_id: Some("kernel.buyer".to_string()),
        host_kernel_id: "kernel.vendor-b".to_string(),
    }
}

fn bundle() -> RuntimeAdmissionBundle {
    RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
        admission_id: "adm-live-1".to_string(),
        binding: binding(),
        workflow_id: "wf-live-1".to_string(),
        workflow_grant_id: "grant-live-1".to_string(),
        step_index: 1,
        destructive: true,
        lease_id: Some("lease-live-1".to_string()),
        governance_receipt_id: Some("gov-live-1".to_string()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    }
}

fn treaty_scope() -> TreatyScope {
    let buyer_key = Keypair::generate();
    let vendor_key = Keypair::generate();
    TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
        participant_public_keys: vec![buyer_key.public_key(), vendor_key.public_key()],
        ladder_manifest_sha256s: vec!["a".repeat(64), "b".repeat(64)],
        allowed_action_classes: vec!["workflow.destructive.vendor_call".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "b".repeat(64),
    }
}

#[path = "runtime_store/authority_readers.rs"]
mod authority_readers;
