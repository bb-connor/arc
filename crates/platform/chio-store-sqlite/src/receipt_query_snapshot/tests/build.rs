//! Task 3: the build pass (C4, C5, C6, C8b, C9, C11b, C15, C17).
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chio_kernel::receipt_query::ReceiptQuery;
use rusqlite::params;

use super::super::db::{SnapshotDb, COUNT_TOTAL, SCOPE_ALL};
use super::super::pass::{build_snapshot, Pass, PassMode, PassProgress};
use super::super::walk::{copy_claims, WalkError};
use super::support::{
    context, keypair, limits, other_keypair, per_call, substitute, target, Fixture, Spec,
};
use crate::receipt_store::support::receipt_signature_verifications;
use crate::receipt_store::BackgroundCheckpointSigner;

fn build(fixture: &Fixture) -> Result<SnapshotDb, WalkError> {
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    build_snapshot(&ctx, target(&ctx), 64 * 1024 * 1024, &mut |_, _| {}).map(|(db, _)| db)
}

fn integrity(result: Result<SnapshotDb, WalkError>) -> String {
    match result {
        Err(WalkError::Integrity(message)) => message,
        Err(other) => panic!("expected an integrity failure, got {other}"),
        Ok(_) => panic!("expected an integrity failure, the build published"),
    }
}

fn mixed_fixture() -> Fixture {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..12);
    fixture.append_child("child-1", 1_700_000_100);
    assert!(fixture.rotate(1_700_000_000 + 6 * 600) > 0);
    fixture.append_varied(12..18);
    fixture
}

#[test]
fn build_authenticates_archive_live_and_tail_once_per_entry() {
    let fixture = mixed_fixture();
    let before = receipt_signature_verifications();
    let db = build(&fixture).unwrap();
    let verified = receipt_signature_verifications() - before;
    assert_eq!(db.tool_row_count().unwrap(), 18);
    // 18 tool receipts and one child receipt: each signature is checked once.
    assert_eq!(verified, 19);
    let total = db.count(SCOPE_ALL, COUNT_TOTAL, 0).unwrap().unwrap().0;
    assert_eq!(total, 18);
}

#[test]
fn c4_a_rewritten_checkpointed_claim_fails_the_batch_root() {
    let fixture = mixed_fixture();
    let original = Spec::varied(13).sign(&keypair());
    let replacement = {
        let mut spec = Spec::varied(13);
        spec.timestamp += 1;
        spec.sign(&keypair())
    };
    // Source row and claim stay consistent, so only the signed root can tell.
    substitute(&fixture, &original, &replacement);
    let message = integrity(build(&fixture));
    assert!(message.contains("merkle_root does not match"), "{message}");
}

#[test]
fn c4_an_edited_checkpoint_row_is_refused() {
    let fixture = mixed_fixture();
    fixture
        .tamper()
        .execute(
            "UPDATE kernel_checkpoints SET merkle_root = ?1 WHERE checkpoint_seq = 2",
            ["00".repeat(32)],
        )
        .unwrap();
    integrity(build(&fixture));
}

#[test]
fn c4_archive_projection_drift_is_refused_at_build() {
    let fixture = mixed_fixture();
    fixture
        .tamper_archive()
        .execute(
            "UPDATE chio_tool_receipts SET tool_name = 'renamed' WHERE seq = 2",
            [],
        )
        .unwrap();
    let message = integrity(build(&fixture));
    assert!(
        message.contains("diverges from its authenticated claim log"),
        "{message}"
    );
}

#[test]
fn c4_a_claim_log_gap_is_refused() {
    let fixture = mixed_fixture();
    fixture
        .tamper()
        .execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = (SELECT MAX(entry_seq) - 1 FROM claim_receipt_log_entries)",
            [],
        )
        .unwrap();
    let message = integrity(build(&fixture));
    assert!(message.contains("gap"), "{message}");
}

/// Insert a validly signed source row with no claim-log entry.
fn insert_orphan(fixture: &Fixture, id: &str) -> i64 {
    let receipt = Spec::new(id, 1_700_100_000).sign(&keypair());
    let tamper = fixture.tamper();
    tamper
        .execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, tool_server, tool_name,
                decision_kind, policy_hash, content_hash, raw_json)
             VALUES (?1, ?2, ?3, ?4, ?5, 'allow', ?6, ?7, ?8)",
            params![
                receipt.id,
                i64::try_from(receipt.timestamp).unwrap(),
                receipt.capability_id,
                receipt.tool_server,
                receipt.tool_name,
                receipt.policy_hash,
                receipt.content_hash,
                serde_json::to_string(&receipt).unwrap()
            ],
        )
        .unwrap();
    tamper.last_insert_rowid()
}

#[test]
fn c5_an_unlogged_source_row_past_the_last_logged_one_fails_the_build() {
    let fixture = mixed_fixture();
    let orphan = insert_orphan(&fixture, "orphan-tail");
    // The per-call path serves the unlogged row.
    let (seqs, _, _) = per_call(
        &fixture.store,
        &ReceiptQuery {
            limit: 200,
            ..ReceiptQuery::default().local_operator_admin()
        },
    );
    assert!(seqs.contains(&u64::try_from(orphan).unwrap()));
    let message = integrity(build(&fixture));
    assert!(message.contains("not a bijection"), "{message}");
}

#[test]
fn c5_an_unlogged_source_row_on_an_empty_history_fails_the_build() {
    let fixture = Fixture::new(4);
    insert_orphan(&fixture, "orphan-only");
    let message = integrity(build(&fixture));
    assert!(message.contains("not a bijection"), "{message}");
}

#[test]
fn c6_live_projection_drift_is_refused_where_the_per_call_filter_drops_the_row() {
    let fixture = mixed_fixture();
    let query = ReceiptQuery {
        tool_name: Some("bash".into()),
        limit: 200,
        ..ReceiptQuery::default().local_operator_admin()
    };
    let (before, _, _) = per_call(&fixture.store, &query);
    let drifted = *before.last().unwrap();
    fixture
        .tamper()
        .execute(
            "UPDATE chio_tool_receipts SET tool_name = 'renamed' WHERE seq = ?1",
            [i64::try_from(drifted).unwrap()],
        )
        .unwrap();
    let (after, _, _) = per_call(&fixture.store, &query);
    assert!(!after.contains(&drifted));
    let message = integrity(build(&fixture));
    assert!(message.contains("diverges"), "{message}");
}

#[test]
fn c8b_corruption_late_in_a_large_batch_fails_without_publishing() {
    let fixture = Fixture::new(8);
    fixture.append_varied(0..8);
    let corrupted = {
        let mut receipt = Spec::varied(6).sign(&keypair());
        receipt.tool_name = "forged".into();
        serde_json::to_string(&receipt).unwrap()
    };
    fixture
        .tamper()
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE entry_seq = 7",
            [corrupted],
        )
        .unwrap();
    integrity(build(&fixture));
}

#[test]
fn c9_a_receipt_signed_by_another_key_inside_a_checkpointed_batch_is_refused() {
    let fixture = mixed_fixture();
    let original = Spec::varied(13).sign(&keypair());
    let replacement = Spec::varied(13).sign(&other_keypair());
    substitute(&fixture, &original, &replacement);
    let message = integrity(build(&fixture));
    assert!(
        message.contains("does not match receipt signer key"),
        "{message}"
    );
}

#[test]
fn c9_a_signer_rollover_between_batches_is_accepted() {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..4);
    fixture
        .store
        .enable_background_checkpoints(BackgroundCheckpointSigner {
            keypair: Arc::new(other_keypair()),
            max_batch: 4,
        })
        .unwrap();
    for index in 4..8 {
        fixture
            .store
            .append_chio_receipt_returning_seq(&Spec::varied(index).sign(&other_keypair()))
            .unwrap();
    }
    fixture.flush();
    let db = build(&fixture).unwrap();
    assert_eq!(db.tool_row_count().unwrap(), 8);
    assert!(db.load_checkpoint(2).unwrap().is_some());
}

#[test]
fn c11b_a_checkpoint_appended_during_the_build_belongs_to_extension() {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..6);
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let target = target(&ctx);
    assert_eq!((target.head, target.checkpoint), (6, 1));
    let mut db = SnapshotDb::open_memory(64 * 1024 * 1024).unwrap();
    let mut pass = Pass::new(PassMode::Build, target);
    assert!(matches!(
        pass.step(&ctx, &mut db).unwrap(),
        PassProgress::Continue
    ));
    // A new checkpoint (entries 5..=8) and a new tail arrive mid-build.
    fixture.append_varied(6..10);
    let result = loop {
        if let PassProgress::Done(result) = pass.step(&ctx, &mut db).unwrap() {
            break result;
        }
    };
    let head = result.head.unwrap();
    assert_eq!(head.body.checkpoint_seq, 1);
    assert!(db.load_checkpoint(2).unwrap().is_none());
    assert_eq!(db.tool_row_count().unwrap(), 6);
    let max_entry: i64 = db
        .connection()
        .unwrap()
        .query_row(
            "SELECT MAX(entry_seq) FROM snapshot_tool_receipt",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(max_entry, 6);
}

#[test]
fn c15_resource_limits_and_cancellation_are_not_integrity_outcomes() {
    let fixture = mixed_fixture();
    let cancel = Arc::new(AtomicBool::new(false));

    let mut capped = limits();
    capped.max_receipt_bytes = 64;
    let ctx = context(&fixture.store, &cancel, capped);
    assert!(matches!(
        build_snapshot(&ctx, target(&ctx), 64 * 1024 * 1024, &mut |_, _| {}),
        Err(WalkError::RowCap { .. })
    ));

    let big = Fixture::new(0);
    big.append_varied(0..400);
    let mut starved = limits();
    starved.step_rows = 400;
    starved.sql_steps = 1;
    let ctx = context(&big.store, &cancel, starved);
    assert!(matches!(
        copy_claims(&ctx, 1, 400),
        Err(WalkError::WalkerBudget)
    ));

    let ctx = context(&fixture.store, &cancel, limits());
    let target = target(&ctx);
    cancel.store(true, Ordering::SeqCst);
    assert!(matches!(
        build_snapshot(&ctx, target, 64 * 1024 * 1024, &mut |_, _| {}),
        Err(WalkError::Cancelled)
    ));
}

#[test]
fn c15_a_locked_archive_is_contention_and_the_step_succeeds_after_release() {
    let fixture = mixed_fixture();
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let holder = fixture.tamper_archive();
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert!(matches!(copy_claims(&ctx, 1, 2), Err(WalkError::Busy(_))));
    holder.execute_batch("COMMIT").unwrap();
    assert_eq!(copy_claims(&ctx, 1, 2).unwrap().len(), 2);
}

#[test]
fn c17_quota_exhaustion_during_the_build_is_typed() {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..200);
    let empty = SnapshotDb::open_memory(64 * 1024 * 1024)
        .unwrap()
        .used_bytes()
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    // Room for the schema and a few pages of rows, not for 200 receipts.
    assert!(matches!(
        build_snapshot(&ctx, target(&ctx), empty + 8 * 4096, &mut |_, _| {}),
        Err(WalkError::Capacity { .. })
    ));
}

/// The production build must use private disk custody on Linux. Changing its
/// mode after publication refuses the next hold and never falls back to memory.
#[cfg(target_os = "linux")]
#[test]
fn linux_snapshot_build_uses_private_disk_and_rechecks_custody() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let fixture = Fixture::new(4);
    fixture.append_varied(0..4);
    let db = build(&fixture).unwrap();
    let path = db
        .connection()
        .unwrap()
        .path()
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
        .expect("Linux production snapshot must have a private backing file");
    let directory = path.parent().unwrap().to_path_buf();
    let file_metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(file_metadata.mode() & 0o777, 0o600);
    assert_eq!(file_metadata.nlink(), 1);
    assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    assert_eq!(db.tool_row_count().unwrap(), 4);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        db.used_bytes(),
        Err(super::super::db::SnapshotDbError::Store(
            chio_kernel::ReceiptStoreError::QuerySnapshot(
                chio_kernel::receipt_query::ReceiptQuerySnapshotError::Invalid(_)
            )
        ))
    ));
    let unknown_tenant = ReceiptQuery::default().authenticated_tenant("unknown-tenant");
    assert!(
        matches!(
            super::super::query::select(&db, &unknown_tenant, 100_000),
            Err(chio_kernel::ReceiptStoreError::QuerySnapshot(
                chio_kernel::receipt_query::ReceiptQuerySnapshotError::Invalid(_)
            ))
        ),
        "cached empty answers still require custody"
    );
    assert!(
        matches!(
            super::super::query::locate(&db, "absent", Some("unknown-tenant")),
            Err(chio_kernel::ReceiptStoreError::QuerySnapshot(
                chio_kernel::receipt_query::ReceiptQuerySnapshotError::Invalid(_)
            ))
        ),
        "point negatives still require custody"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(db.tool_row_count().unwrap(), 4);
    drop(db);
    assert!(!path.exists(), "owned file is cleaned up after close");
    assert!(
        !directory.exists(),
        "owned directory is cleaned up after close"
    );
}
