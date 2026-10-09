use super::*;
use crate::receipt_query_snapshot::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn start(store: Arc<SqliteReceiptStore>) -> ReceiptQuerySnapshots {
    let snapshots = ReceiptQuerySnapshots::start(
        store,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while snapshots.status().state != ReceiptQuerySnapshotState::Ready {
        assert!(
            Instant::now() < deadline,
            "snapshot did not become ready: {:?}",
            snapshots.status()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    snapshots
}

#[test]
fn authenticated_export_preserves_mixed_archived_proofs_and_claim_sequences() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteReceiptStore::open(directory.path().join("live.db")).unwrap());
    for (id, tenant) in [("old-a", "a"), ("old-b", "b")] {
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                id,
                "cap",
                100,
                Some(tenant),
            ))
            .unwrap();
    }
    store
        .append_child_receipt(&child_receipt_with_ts_and_key(
            "child",
            100,
            &evidence_receipt_keypair(),
        ))
        .unwrap();
    let canonical = store.receipts_canonical_bytes_range(1, 3).unwrap();
    let checkpoint = build_checkpoint(
        1,
        1,
        3,
        &canonical.into_iter().map(|(_, b)| b).collect::<Vec<_>>(),
        &evidence_receipt_keypair(),
    )
    .unwrap();
    store.store_checkpoint(&checkpoint).unwrap();
    assert_eq!(
        store
            .archive_receipts_before(101, directory.path().join("archive.db").to_str().unwrap())
            .unwrap(),
        2
    );
    store
        .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
            "live-a",
            "cap",
            102,
            Some("a"),
        ))
        .unwrap();
    let snapshots = start(Arc::clone(&store));
    let query = EvidenceExportQuery::tenant_scoped("a");
    let (bundle, transparency, watermark) = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap();
    assert_eq!(
        bundle
            .tool_receipts
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![1, 4]
    );
    assert_eq!(watermark.through_entry_seq, 4);
    assert_eq!(
        bundle.child_receipt_scope,
        EvidenceChildReceiptScope::OmittedNoJoinPath
    );
    assert!(bundle.child_receipts.is_empty());
    assert!(bundle.retention.live_db_size_bytes.is_none());
    assert!(bundle.retention.oldest_live_receipt_timestamp.is_none());
    assert_eq!(bundle.inclusion_proofs.len(), 1);
    assert_eq!(bundle.uncheckpointed_receipts[0].seq, 4);
    let bytes =
        chio_core::canonical::canonical_json_bytes(&bundle.tool_receipts[0].receipt).unwrap();
    assert!(bundle.inclusion_proofs[0].verify(&bytes, &checkpoint.body.merkle_root));
    assert_eq!(transparency.publications.len(), 1);
    let (admin, _, _) = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::admin_all())
        .unwrap();
    assert_eq!(admin.child_receipts.len(), 1);
    assert_eq!(admin.child_receipts[0].seq, 1);
    let mut local = store.build_evidence_export_bundle(&query).unwrap();
    assert_eq!(local.retention.oldest_live_receipt_timestamp, Some(102));
    local.retention = bundle.retention.clone();
    assert_eq!(
        serde_json::to_value(&bundle).unwrap(),
        serde_json::to_value(local).unwrap()
    );
    snapshots.shutdown();
}

#[test]
fn authenticated_export_refuses_changed_selected_leaf_and_invalidates_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.db");
    let store = Arc::new(SqliteReceiptStore::open(&path).unwrap());
    let receipt = receipt_with_ts_and_tenant("selected", "cap", 100, Some("a"));
    store.append_chio_receipt_returning_seq(&receipt).unwrap();
    let snapshots = start(store);
    let connection = Connection::open(path).unwrap();
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE claim_receipt_log_entries SET raw_json = '{}' WHERE receipt_id = ?1",
                [receipt.id]
            )
            .unwrap(),
        1
    );
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::tenant_scoped("a"))
        .unwrap_err();
    assert!(
        matches!(
            error,
            EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(
                chio_kernel::ReceiptQuerySnapshotError::Invalid(_)
            ))
        ),
        "{error:?}"
    );
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
}

#[test]
fn archived_late_subject_export_uses_authenticated_attribution_across_pages() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteReceiptStore::open(directory.path().join("live.db")).unwrap());
    store
        .enable_background_checkpoints(crate::BackgroundCheckpointSigner {
            keypair: Arc::new(evidence_receipt_keypair()),
            max_batch: 20,
        })
        .unwrap();
    for index in 0..420 {
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                &format!("r-{index}"),
                "cap",
                100,
                Some("a"),
            ))
            .unwrap();
    }
    store.flush_receipt_writes().unwrap();
    assert_eq!(
        store
            .archive_receipts_before(101, directory.path().join("archive.db").to_str().unwrap())
            .unwrap(),
        420
    );
    let issuer = Keypair::from_seed(&[13; 32]);
    let subject = Keypair::from_seed(&[14; 32]);
    store
        .record_capability_snapshot(&capability_with_id("cap", &subject, &issuer, None), None)
        .unwrap();
    let snapshots = start(store);
    let mut query = EvidenceExportQuery::tenant_scoped("a");
    query.agent_subject = Some(subject.public_key().to_hex());
    let before = crate::receipt_store::retained_read::unrecorded_lineage_reads_for_test();
    let (bundle, _, _) = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 420);
    assert_eq!(bundle.inclusion_proofs.len(), 420);
    assert_eq!(
        crate::receipt_store::retained_read::unrecorded_lineage_reads_for_test(),
        before,
        "export must not repeat the archive-wide attribution walk on every page"
    );
    snapshots.shutdown();
}

#[test]
fn authenticated_export_refuses_a_changed_selected_child_payload() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.db");
    let store = Arc::new(SqliteReceiptStore::open(&path).unwrap());
    store
        .append_child_receipt(&child_receipt_with_ts_and_key(
            "selected-child",
            100,
            &evidence_receipt_keypair(),
        ))
        .unwrap();
    let snapshots = start(store);
    let connection = Connection::open(path).unwrap();
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )
        .unwrap();
    assert_eq!(connection.execute("UPDATE claim_receipt_log_entries SET raw_json = '{}' WHERE receipt_id = 'selected-child'", []).unwrap(), 1);
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::admin_all())
        .unwrap_err();
    assert!(
        matches!(
            error,
            EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(
                chio_kernel::ReceiptQuerySnapshotError::Invalid(_)
            ))
        ),
        "{error:?}"
    );
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
}

#[test]
fn current_unsigned_lineage_must_match_the_subject_captured_by_selection() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.db");
    let store = Arc::new(SqliteReceiptStore::open(&path).unwrap());
    let issuer = Keypair::from_seed(&[13; 32]);
    let original_subject = Keypair::from_seed(&[14; 32]);
    store
        .record_capability_snapshot(
            &capability_with_id("cap", &original_subject, &issuer, None),
            None,
        )
        .unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
            "selected",
            "cap",
            100,
            Some("a"),
        ))
        .unwrap();
    let snapshots = start(Arc::clone(&store));
    let replacement = capability_with_id("cap", &Keypair::from_seed(&[15; 32]), &issuer, None);
    let connection = Connection::open(path).unwrap();
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )
        .unwrap();
    assert_eq!(connection.execute("UPDATE capability_lineage SET subject_key = ?1, signed_capability_json = ?2 WHERE capability_id = 'cap'", params![replacement.subject.to_hex(), serde_json::to_string(&replacement).unwrap()]).unwrap(), 1);
    let mut query = EvidenceExportQuery::tenant_scoped("a");
    query.agent_subject = Some(original_subject.public_key().to_hex());
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap_err();
    assert!(
        matches!(&error, EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(chio_kernel::ReceiptQuerySnapshotError::Invalid(reason))) if reason.contains("unsigned capability attribution")),
        "{error:?}"
    );
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
}

#[test]
fn deleted_current_lineage_refuses_known_captured_unsigned_attribution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.db");
    let store = Arc::new(SqliteReceiptStore::open(&path).unwrap());
    let issuer = Keypair::from_seed(&[13; 32]);
    let subject = Keypair::from_seed(&[14; 32]);
    store
        .record_capability_snapshot(&capability_with_id("cap", &subject, &issuer, None), None)
        .unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
            "selected",
            "cap",
            100,
            Some("a"),
        ))
        .unwrap();
    let snapshots = start(store);
    let mut query = EvidenceExportQuery::tenant_scoped("a");
    query.agent_subject = Some(subject.public_key().to_hex());
    let (baseline, _, _) = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap();
    assert_eq!(baseline.tool_receipts.len(), 1);
    assert_eq!(baseline.capability_lineage.len(), 1);
    let connection = Connection::open(path).unwrap();
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "DELETE FROM capability_lineage WHERE capability_id = 'cap'",
                []
            )
            .unwrap(),
        1
    );
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap_err();
    assert!(
        matches!(&error, EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(chio_kernel::ReceiptQuerySnapshotError::Invalid(reason))) if reason.contains("required unsigned attribution")),
        "{error:?}"
    );
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
}

#[test]
fn originally_unknown_unsigned_attribution_keeps_empty_lineage_export_semantics() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteReceiptStore::open(directory.path().join("live.db")).unwrap());
    store
        .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
            "selected",
            "unknown-cap",
            100,
            Some("a"),
        ))
        .unwrap();
    let snapshots = start(store);
    let (bundle, _, _) = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::tenant_scoped("a"))
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 1);
    assert!(bundle.capability_lineage.is_empty());
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    snapshots.shutdown();
}
