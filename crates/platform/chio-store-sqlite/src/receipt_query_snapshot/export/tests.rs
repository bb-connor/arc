use super::*;
use crate::evidence_export::tests::{
    child_receipt_with_ts_and_key, evidence_receipt_keypair, receipt_with_ts_and_tenant,
};
use crate::receipt_query_snapshot::{ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState};
use crate::receipt_store::SqliteReceiptStore;
use chio_kernel::ReceiptStore;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::{Duration, Instant};

type AfterSelectionHook = Box<dyn FnOnce(u64)>;
thread_local! { static AFTER_SELECTION: RefCell<Option<AfterSelectionHook>> = RefCell::new(None); }
pub(super) fn after_selection(through: u64) {
    let hook = AFTER_SELECTION.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook(through);
    }
}

fn wait_until_ready(snapshots: &ReceiptQuerySnapshots) {
    // The notification carries readiness; this timeout only bounds a hung test.
    let status = snapshots.wait_for_recovery(Duration::from_secs(600), |status| {
        !matches!(
            status.state,
            ReceiptQuerySnapshotState::WaitingForWriterSeed
                | ReceiptQuerySnapshotState::Building { .. }
        )
    });
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready, "{status:?}");
}

fn fixture(
    count: u64,
    batch: u64,
    mut config: ReceiptQuerySnapshotConfig,
) -> (
    tempfile::TempDir,
    Arc<SqliteReceiptStore>,
    Arc<ReceiptQuerySnapshots>,
) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteReceiptStore::open(directory.path().join("live.db")).unwrap());
    if batch > 0 {
        store
            .enable_background_checkpoints(crate::BackgroundCheckpointSigner {
                keypair: Arc::new(evidence_receipt_keypair()),
                max_batch: batch,
            })
            .unwrap();
    }
    for index in 0..count {
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                &format!("r-{index}"),
                "cap",
                100 + index,
                Some("a"),
            ))
            .unwrap();
    }
    store.flush_receipt_writes().unwrap();
    config.recertify_interval = Duration::from_secs(3_600);
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(Arc::clone(&store), config).unwrap());
    wait_until_ready(&snapshots);
    (directory, store, snapshots)
}

fn budget_error(error: EvidenceExportError) -> String {
    match error {
        EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(
            ReceiptQuerySnapshotError::WorkBudgetExhausted(reason),
        )) => reason,
        other => panic!("expected a request budget refusal, got {other:?}"),
    }
}

#[test]
fn receipt_allowance_accepts_its_exact_boundary_and_refuses_without_truncation() {
    let (_directory, store, snapshots) = fixture(3, 0, ReceiptQuerySnapshotConfig::default());
    let query = EvidenceExportQuery::tenant_scoped("a");
    let (bundle, _, _) = snapshots
        .build_export(
            &query,
            Limits {
                receipts: 3,
                ..Limits::default()
            },
        )
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 3);
    let reason = budget_error(
        snapshots
            .build_export(
                &query,
                Limits {
                    receipts: 2,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("receipt allowance"));
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        store
            .build_evidence_export_bundle(&query)
            .unwrap()
            .tool_receipts
            .len(),
        3
    );
    assert_eq!(
        snapshots
            .query_receipts(&query.as_receipt_query(None))
            .unwrap()
            .total_count,
        3
    );
    snapshots.shutdown();
}

#[test]
fn complete_checkpoint_prefix_and_proof_leaf_allowances_have_explicit_boundaries() {
    let (_directory, store, snapshots) = fixture(3, 1, ReceiptQuerySnapshotConfig::default());
    let query = EvidenceExportQuery::tenant_scoped("a");
    let (bundle, _, _) = snapshots
        .build_export(
            &query,
            Limits {
                checkpoints: 3,
                proof_leaves: 3,
                ..Limits::default()
            },
        )
        .unwrap();
    assert_eq!(bundle.checkpoints.len(), 3);
    assert_eq!(bundle.inclusion_proofs.len(), 3);
    let reason = budget_error(
        snapshots
            .build_export(
                &query,
                Limits {
                    checkpoints: 2,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("narrowing a recent query cannot reduce this prefix"));
    assert!(reason.contains("local operator export"));
    let mut recent = query.clone();
    recent.since = Some(102);
    let reason = budget_error(
        snapshots
            .build_export(
                &recent,
                Limits {
                    checkpoints: 2,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("narrowing a recent query cannot reduce this prefix"));
    let local = store.build_evidence_export_bundle(&recent).unwrap();
    assert_eq!(local.tool_receipts.len(), 1);
    assert_eq!(local.checkpoints.len(), 3);
    assert_eq!(local.inclusion_proofs.len(), 1);
    let reason = budget_error(
        snapshots
            .build_export(
                &query,
                Limits {
                    proof_leaves: 2,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("proof-leaf allowance"));
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    snapshots.shutdown();
}

#[test]
fn payload_byte_refusal_does_not_invalidate_a_healthy_snapshot() {
    let (_directory, _store, snapshots) = fixture(1, 0, ReceiptQuerySnapshotConfig::default());
    let query = EvidenceExportQuery::tenant_scoped("a");
    let reason = budget_error(
        snapshots
            .build_export(
                &query,
                Limits {
                    bytes: 512,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("byte allowance"));
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        snapshots
            .build_export(&query, Limits::default())
            .unwrap()
            .0
            .tool_receipts
            .len(),
        1
    );
    snapshots.shutdown();
}

#[test]
fn child_and_tool_counts_share_one_receipt_allowance_without_truncation() {
    let (_directory, store, snapshots) = fixture(1, 0, ReceiptQuerySnapshotConfig::default());
    snapshots.shutdown();
    for index in 0..2 {
        store
            .append_child_receipt(&child_receipt_with_ts_and_key(
                &format!("child-{index}"),
                100 + index,
                &evidence_receipt_keypair(),
            ))
            .unwrap();
    }
    let snapshots =
        ReceiptQuerySnapshots::start(Arc::clone(&store), ReceiptQuerySnapshotConfig::default())
            .unwrap();
    wait_until_ready(&snapshots);
    let query = EvidenceExportQuery::admin_all();
    let (bundle, _, _) = snapshots
        .build_export(
            &query,
            Limits {
                receipts: 3,
                ..Limits::default()
            },
        )
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 1);
    assert_eq!(bundle.child_receipts.len(), 2);
    let reason = budget_error(
        snapshots
            .build_export(
                &query,
                Limits {
                    receipts: 2,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("receipt allowance"));
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        store
            .build_evidence_export_bundle(&query)
            .unwrap()
            .child_receipts
            .len(),
        2
    );
    snapshots.shutdown();
}

#[test]
fn publication_core_and_binding_bytes_are_combined_before_metadata_decode() {
    let (directory, _store, snapshots) = fixture(
        1,
        1,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    );
    let query = EvidenceExportQuery::tenant_scoped("a");
    let (bundle, _, _) = snapshots.build_export(&query, Limits::default()).unwrap();
    let connection = rusqlite::Connection::open(directory.path().join("live.db")).unwrap();
    let core_bytes: i64 = connection.query_row(
        "SELECT length(CAST(publication_schema AS BLOB)) + length(CAST(merkle_root AS BLOB)) + length(CAST(kernel_key AS BLOB)) + COALESCE(length(CAST(previous_checkpoint_sha256 AS BLOB)), 0) FROM checkpoint_publication_metadata WHERE checkpoint_seq = 1",
        [], |row| row.get(0),
    ).unwrap();
    let binding = "x".repeat(1_024);
    connection.execute(
        "INSERT INTO checkpoint_publication_trust_anchor_bindings (checkpoint_seq, binding_json) VALUES (1, ?1)",
        [&binding],
    ).unwrap();
    let mut consumed = ByteBudget::new(Limits::default().bytes);
    consumed.charge(&bundle.query).unwrap();
    for record in &bundle.tool_receipts {
        consumed.charge(record).unwrap();
    }
    for checkpoint in &bundle.checkpoints {
        consumed.charge(checkpoint).unwrap();
    }
    let consumed = Limits::default().bytes - consumed.remaining();
    let allowance =
        consumed + crate::integer::count(binding.len()) + u64::try_from(core_bytes).unwrap() - 1;
    let reason = budget_error(
        snapshots
            .build_export(
                &query,
                Limits {
                    bytes: allowance,
                    ..Limits::default()
                },
            )
            .unwrap_err(),
    );
    assert!(reason.contains("byte allowance"));
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    snapshots.shutdown();
}

#[test]
fn signed_checkpoint_time_rewrite_cannot_replace_the_authenticated_checkpoint() {
    let (directory, store, snapshots) = fixture(
        1,
        1,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    );
    let query = EvidenceExportQuery::tenant_scoped("a");
    let mut replacement = store
        .build_evidence_export_bundle(&query)
        .unwrap()
        .checkpoints
        .remove(0);
    replacement.body.issued_at += 1;
    let issued_at = i64::try_from(replacement.body.issued_at).unwrap();
    replacement.signature =
        evidence_receipt_keypair().sign(&canonical_json_bytes(&replacement.body).unwrap());
    let connection = rusqlite::Connection::open(directory.path().join("live.db")).unwrap();
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )
        .unwrap();
    assert_eq!(connection.execute("UPDATE kernel_checkpoints SET issued_at = ?1, statement_json = ?2, signature = ?3 WHERE checkpoint_seq = 1", rusqlite::params![issued_at, serde_json::to_string(&replacement.body).unwrap(), replacement.signature.to_hex()]).unwrap(), 1);
    assert_eq!(connection.execute("UPDATE checkpoint_publication_metadata SET published_at = ?1 WHERE checkpoint_seq = 1", [issued_at]).unwrap(), 1);
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap_err();
    assert!(
        matches!(&error, EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Invalid(reason))) if reason.contains("signed checkpoint the snapshot authenticated")),
        "{error:?}"
    );
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
}

#[test]
fn lineage_shutdown_after_selection_refuses_the_materialized_export() {
    let (_directory, _store, snapshots) = fixture(1, 0, ReceiptQuerySnapshotConfig::default());
    let stopped = Arc::clone(&snapshots);
    AFTER_SELECTION.with(|hook| *hook.borrow_mut() = Some(Box::new(move |_| stopped.shutdown())));
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::tenant_scoped("a"))
        .unwrap_err();
    assert!(
        matches!(
            error,
            EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(
                ReceiptQuerySnapshotError::Unavailable(_)
            ))
        ),
        "{error:?}"
    );
}

#[test]
fn benign_head_advancement_during_multiple_payload_pages_does_not_starve_export() {
    let (_directory, store, snapshots) = fixture(
        64,
        0,
        ReceiptQuerySnapshotConfig {
            page_bytes: 1,
            extension_tick: Duration::from_millis(1),
            ..ReceiptQuerySnapshotConfig::default()
        },
    );
    let stopped = Arc::new(AtomicBool::new(false));
    let appended = Arc::new(AtomicU64::new(0));
    let producer_stop = Arc::clone(&stopped);
    let producer_count = Arc::clone(&appended);
    let producer_store = Arc::clone(&store);
    let producer = std::thread::spawn(move || {
        for index in 0..2_000 {
            if producer_stop.load(Ordering::SeqCst) {
                break;
            }
            producer_store
                .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                    &format!("background-{index}"),
                    "other",
                    1_000 + index,
                    Some("b"),
                ))
                .unwrap();
            producer_count.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let hook_snapshots = Arc::clone(&snapshots);
    let progress = Arc::clone(&appended);
    AFTER_SELECTION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |captured| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while progress.load(Ordering::SeqCst) == 0
                || hook_snapshots
                    .status()
                    .watermark
                    .as_ref()
                    .is_none_or(|watermark| watermark.through_entry_seq <= captured)
            {
                assert!(
                    Instant::now() < deadline,
                    "benign extension did not advance the head"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }))
    });
    let result = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::tenant_scoped("a"));
    stopped.store(true, Ordering::SeqCst);
    producer.join().unwrap();
    let (bundle, _, watermark) = result.unwrap();
    assert_eq!(bundle.tool_receipts.len(), 64);
    assert!(bundle
        .tool_receipts
        .iter()
        .all(|row| row.receipt.tenant_id.as_deref() == Some("a")));
    assert!(appended.load(Ordering::SeqCst) > 0);
    assert!(snapshots.status().watermark.unwrap().through_entry_seq > watermark.through_entry_seq);
    snapshots.shutdown();
}

#[test]
fn missing_owned_checkpoint_prefix_invalidates_the_shared_snapshot() {
    let (_directory, _store, snapshots) = fixture(3, 1, ReceiptQuerySnapshotConfig::default());
    let corrupted = Arc::clone(&snapshots);
    AFTER_SELECTION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |_| {
            let (published, _) = corrupted.inner.ready().unwrap();
            let owned = published.owned.lock().unwrap();
            assert_eq!(
                owned
                    .db
                    .connection()
                    .unwrap()
                    .execute("DELETE FROM snapshot_checkpoint WHERE seq = 1", [])
                    .unwrap(),
                1
            );
        }))
    });
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::tenant_scoped("a"))
        .unwrap_err();
    assert!(
        matches!(&error, EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Invalid(reason))) if reason.contains("checkpoint prefix")),
        "{error:?}"
    );
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
}

#[test]
fn divergent_publication_enrichment_refuses_export_but_preserves_owned_receipt_queries() {
    let (directory, _store, snapshots) = fixture(
        1,
        1,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    );
    let path = directory.path().join("live.db");
    AFTER_SELECTION.with(|hook| *hook.borrow_mut() = Some(Box::new(move |_| {
        let connection = rusqlite::Connection::open(path).unwrap();
        connection.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false).unwrap();
        assert_eq!(connection.execute("UPDATE checkpoint_publication_metadata SET publication_schema = 'unsupported-export-metadata' WHERE checkpoint_seq = 1", []).unwrap(), 1);
    })));
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::tenant_scoped("a"))
        .unwrap_err();
    assert_eq!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Ready,
        "{error:?}"
    );
    assert!(
        matches!(
            &error,
            EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::ExportRefused(reason)))
                if reason == "checkpoint 1 publication metadata diverges from persisted projection"
        ),
        "{error:?}"
    );
    assert_eq!(
        snapshots
            .query_receipts(&EvidenceExportQuery::tenant_scoped("a").as_receipt_query(None))
            .unwrap()
            .total_count,
        1
    );
    snapshots.shutdown();
}

#[test]
fn child_rotation_after_capture_preserves_admin_export_and_snapshot_custody() {
    let (directory, store, first) = fixture(1, 1, ReceiptQuerySnapshotConfig::default());
    first.shutdown();
    store
        .append_child_receipt(&child_receipt_with_ts_and_key(
            "rotating-child",
            100,
            &evidence_receipt_keypair(),
        ))
        .unwrap();
    store.flush_receipt_writes().unwrap();
    let snapshots = ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )
    .unwrap();
    wait_until_ready(&snapshots);
    let archive = directory.path().join("archive.db");
    let rotated_store = Arc::clone(&store);
    let archive_check = archive.clone();
    AFTER_SELECTION.with(|hook| *hook.borrow_mut() = Some(Box::new(move |_| {
        assert_eq!(rotated_store.archive_receipts_before(101, archive.to_str().unwrap()).unwrap(), 1);
        let archived = rusqlite::Connection::open(archive_check).unwrap();
        assert_eq!(archived.query_row("SELECT COUNT(*) FROM claim_receipt_log_entries WHERE receipt_kind = 'child_receipt'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    })));
    let (bundle, _, _) = snapshots
        .build_evidence_export_bundle_with_transparency(&EvidenceExportQuery::admin_all())
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 1);
    assert_eq!(bundle.child_receipts.len(), 1);
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    snapshots.shutdown();
}

#[test]
fn malformed_mutable_publication_binding_refuses_export_with_triggers_enabled() {
    let (directory, _store, snapshots) = fixture(
        1,
        1,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    );
    let connection = rusqlite::Connection::open(directory.path().join("live.db")).unwrap();
    assert!(connection
        .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
        .unwrap());
    connection.execute(
        "INSERT INTO checkpoint_publication_trust_anchor_bindings (checkpoint_seq, binding_json) VALUES (1, '{}')",
        [],
    ).unwrap();
    let query = EvidenceExportQuery::tenant_scoped("a");
    let error = snapshots
        .build_evidence_export_bundle_with_transparency(&query)
        .unwrap_err();
    assert!(
        matches!(
            &error,
            EvidenceExportError::ReceiptStore(ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::ExportRefused(reason)))
                if reason == "urn:chio:error:attest:signed-json-invalid-shape"
        ),
        "{error:?}"
    );
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        snapshots
            .query_receipts(&query.as_receipt_query(None))
            .unwrap()
            .total_count,
        1
    );
    snapshots.shutdown();
}
