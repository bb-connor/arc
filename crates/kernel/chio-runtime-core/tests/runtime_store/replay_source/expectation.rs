use super::*;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, RuntimeReplaySourcePort,
    RuntimeReplaySourceSnapshotV1,
};

fn assert_no_seal_after_mismatch(
    store: &SqliteRuntimeOrchestrationStore,
    raw: &Connection,
    expected: &RuntimeReplaySourceSnapshotV1,
) -> TestResult {
    let before = raw_snapshot(raw)?;
    assert_code(
        store.seal_expected_legacy_replay_source(expected),
        "runtime_replay_source_invalid",
    );
    assert!(store.load_legacy_replay_source_seal(&binding()?)?.is_none());
    assert_eq!(
        raw_snapshot(raw)?,
        before,
        "mismatched expectation must install no seal or barriers"
    );
    store.consume_destructive_lease("mismatch-probe", "probe-owner")?;
    store.release_destructive_lease("mismatch-probe", "probe-owner")?;
    assert_eq!(raw_snapshot(raw)?, before);
    Ok(())
}

#[test]
fn preview_is_read_only_and_unchanged_source_seals_and_retries_exactly() -> TestResult {
    for populated in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("preview.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        if populated {
            seed_inventory(&store)?;
        }
        let raw = Connection::open(&path)?;
        let before = raw_snapshot(&raw)?;
        let binding = binding()?;
        let expected = store.preview_legacy_replay_source(&binding)?;
        assert_eq!(raw_snapshot(&raw)?, before);
        assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
        assert_eq!(expected.source_id(), binding.source_id());
        assert_eq!(
            expected.runtime_authority_id(),
            binding.runtime_authority_id()
        );
        assert_eq!(
            expected.destination_authority_id(),
            binding.destination_authority_id()
        );
        let identity = chio_sqlite_file_identity::main_database_file_identity(&raw)?;
        assert_eq!(
            (expected.device(), expected.inode(), expected.link_count()),
            (identity.device, identity.inode, identity.link_count)
        );
        assert!(
            RuntimeReplaySourcePort::verify_exact(&store, &expected).is_err(),
            "a preview cannot attest installed barriers"
        );
        assert_eq!(raw_snapshot(&raw)?, before);
        let repeat = store.preview_legacy_replay_source(&binding)?;
        assert_eq!(repeat.canonical_bytes(), expected.canonical_bytes());

        let seal = store.seal_expected_legacy_replay_source(&expected)?;
        assert_eq!(
            seal.canonical_bytes()?.as_slice(),
            expected.canonical_bytes()
        );
        assert_eq!(seal.inventory_sha256(), expected.inventory_sha256());
        if populated {
            assert_inventory(&seal);
        } else {
            assert!(seal.markers().is_empty());
        }
        RuntimeReplaySourcePort::verify_exact(&store, &expected)?;
        assert_eq!(store.seal_expected_legacy_replay_source(&expected)?, seal);
        // The original standalone API retains its exact-reseal semantics.
        assert_eq!(store.seal_legacy_replay_source(&binding)?, seal);
        drop(store);
        let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
        RuntimeReplaySourcePort::verify_exact(&reopened, &expected)?;
        assert_eq!(
            reopened.seal_expected_legacy_replay_source(&expected)?,
            seal
        );
    }
    Ok(())
}

#[test]
fn every_inventory_mutation_after_preview_rejects_before_sealing() -> TestResult {
    for (table, key, _) in TABLES {
        for mutation in ["insert", "update", "delete"] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("changed-inventory.sqlite3");
            let store = SqliteRuntimeOrchestrationStore::open(&path)?;
            seed_inventory(&store)?;
            let expected = store.preview_legacy_replay_source(&binding()?)?;
            let raw = Connection::open(&path)?;
            let sql = match mutation {
                "insert" => format!("INSERT INTO {table}({key}, admission_id) VALUES ('new-resource', 'new-owner')"),
                "update" => format!("UPDATE {table} SET admission_id = 'different-owner' WHERE {key} = 'resource-a'"),
                _ => format!("DELETE FROM {table} WHERE {key} = 'resource-a'"),
            };
            assert_eq!(raw.execute(&sql, [])?, 1);
            assert_no_seal_after_mismatch(&store, &raw, &expected)?;
        }
    }
    Ok(())
}

#[test]
fn empty_preview_cannot_silently_seal_a_new_marker_of_any_kind() -> TestResult {
    for (table, key, _) in TABLES {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("empty-to-populated.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let expected = store.preview_legacy_replay_source(&binding()?)?;
        let raw = Connection::open(&path)?;
        raw.execute(
            &format!(
                "INSERT INTO {table}({key}, admission_id) VALUES ('late-resource', 'late-owner')"
            ),
            [],
        )?;
        assert_no_seal_after_mismatch(&store, &raw, &expected)?;
    }
    Ok(())
}

#[test]
fn identical_inventory_in_a_different_file_cannot_satisfy_a_preview() -> TestResult {
    let directory = tempfile::tempdir()?;
    let original_path = directory.path().join("original.sqlite3");
    let replacement_path = directory.path().join("replacement.sqlite3");
    let original = SqliteRuntimeOrchestrationStore::open(&original_path)?;
    let replacement = SqliteRuntimeOrchestrationStore::open(&replacement_path)?;
    seed_inventory(&original)?;
    seed_inventory(&replacement)?;
    let expected = original.preview_legacy_replay_source(&binding()?)?;
    let raw = Connection::open(&replacement_path)?;
    assert_no_seal_after_mismatch(&replacement, &raw, &expected)?;
    assert!(original
        .load_legacy_replay_source_seal(&binding()?)?
        .is_none());
    original.seal_expected_legacy_replay_source(&expected)?;
    RuntimeReplaySourcePort::verify_exact(&original, &expected)?;
    Ok(())
}

#[test]
fn hard_link_created_after_preview_rejects_without_retiring_the_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("preview-link.sqlite3");
    let link = directory.path().join("additional-link.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    let raw = Connection::open(&path)?;
    std::fs::hard_link(&path, &link)?;
    assert_no_seal_after_mismatch(&store, &raw, &expected)?;
    std::fs::remove_file(&link)?;
    store.seal_expected_legacy_replay_source(&expected)?;
    RuntimeReplaySourcePort::verify_exact(&store, &expected)?;
    Ok(())
}

#[test]
fn sealed_and_partially_sealed_sources_cannot_produce_a_fresh_preview() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("sealed-preview.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = binding()?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    let raw = Connection::open(&path)?;
    let before = raw_snapshot(&raw)?;
    assert_code(
        store.preview_legacy_replay_source(&binding),
        "runtime_replay_source_sealed",
    );
    assert_eq!(raw_snapshot(&raw)?, before);
    store.verify_legacy_replay_source_seal(&seal)?;
    raw.execute_batch("DROP TRIGGER runtime_replay_source_lease_no_insert")?;
    let partial = raw_snapshot(&raw)?;
    assert_code(
        store.preview_legacy_replay_source(&binding),
        "runtime_replay_source_sealed",
    );
    assert_eq!(raw_snapshot(&raw)?, partial);
    Ok(())
}

#[test]
fn real_sqlite_source_port_has_no_unsealed_or_mismatched_success_fallback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("port.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = binding()?;
    let source = AdmissionIdentifier::try_new("source_id", binding.source_id())?;
    let runtime =
        AdmissionIdentifier::try_new("runtime_authority_id", binding.runtime_authority_id())?;
    let destination = AdmissionIdentifier::try_new(
        "destination_authority_id",
        binding.destination_authority_id(),
    )?;
    let port: &dyn RuntimeReplaySourcePort = &store;
    let stale = port.preview(&source, &runtime, &destination)?;
    assert!(matches!(
        port.verify_exact(&stale),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    seed_inventory(&store)?;
    let before = raw_snapshot(&Connection::open(&path)?)?;
    assert!(matches!(
        port.seal_exact(&stale),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert_eq!(raw_snapshot(&Connection::open(&path)?)?, before);
    let current = port.preview(&source, &runtime, &destination)?;
    port.seal_exact(&current)?;
    port.verify_exact(&current)?;
    port.seal_exact(&current)?;
    assert!(matches!(
        port.verify_exact(&stale),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        port.seal_exact(&stale),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        port.preview(&source, &runtime, &destination),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    port.verify_exact(&current)?;
    Ok(())
}

#[test]
fn structurally_valid_rehashed_snapshot_data_cannot_authorize_a_different_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("untrusted-snapshot.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    let raw = Connection::open(&path)?;
    let original: serde_json::Value = serde_json::from_slice(expected.canonical_bytes())?;
    for alteration in ["barrier", "identity", "historical-owner"] {
        let mut changed = original.clone();
        match alteration {
            "barrier" => {
                changed["body"]["barrierSha256"] =
                    serde_json::json!(if expected.barrier_sha256() == "f".repeat(64) {
                        "e".repeat(64)
                    } else {
                        "f".repeat(64)
                    })
            }
            "identity" => {
                changed["body"]["device"] =
                    serde_json::json!(if expected.device() == 0 { "1" } else { "0" })
            }
            _ => changed["body"]["markers"][0]["admissionId"] = serde_json::json!("forged-owner"),
        }
        // The destination decoder checks data integrity, not source authority.
        // A hostile caller can recompute a digest over different canonical data.
        let body = chio_core_types::crypto::canonical_json_bytes(&changed["body"])?;
        let mut preimage = b"chio.runtime-replay-source-seal.v1\0".to_vec();
        preimage.extend_from_slice(&body);
        changed["inventorySha256"] =
            serde_json::json!(chio_core_types::crypto::sha256_hex(&preimage));
        let untrusted = RuntimeReplaySourceSnapshotV1::from_canonical_bytes(
            &chio_core_types::crypto::canonical_json_bytes(&changed)?,
        )?;
        assert_no_seal_after_mismatch(&store, &raw, &untrusted)?;
    }
    let mut noncanonical = expected.canonical_bytes().to_vec();
    noncanonical.push(b' ');
    assert!(RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&noncanonical).is_err());
    store.seal_expected_legacy_replay_source(&expected)?;
    RuntimeReplaySourcePort::verify_exact(&store, &expected)?;
    Ok(())
}

#[test]
fn preview_rejects_invalid_inventory_and_noncanonical_legacy_schema_without_changes() -> TestResult
{
    for corruption in [
        "INSERT INTO runtime_consumed_leases(lease_id, admission_id) VALUES (X'FF', 'owner')",
        "CREATE TRIGGER unrelated_preview_hook BEFORE INSERT ON runtime_consumed_leases BEGIN SELECT 1; END",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("invalid-preview.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let raw = Connection::open(&path)?;
        raw.execute_batch(corruption)?;
        let before = raw_snapshot(&raw)?;
        assert_code(store.preview_legacy_replay_source(&binding()?), "runtime_replay_source_invalid");
        assert!(store.load_legacy_replay_source_seal(&binding()?)?.is_none());
        assert_eq!(raw_snapshot(&raw)?, before);
    }
    Ok(())
}
