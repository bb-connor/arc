use super::super::support;
use super::{
    copy_checkpoint_prefix_to_attached_archive, unique_db_path, ReceiptStoreError,
    SqliteReceiptStore,
};

/// A botched rotation can record a watermark and then fail before removing the
/// orphaned claim-log rows it left behind. Re-running repair rounds to the same
/// boundary the watermark already covers; an unconditional re-insert would hit
/// the ledger's monotonic-insert trigger and roll the whole repair back, so the
/// store could never be cleaned up. Repair must skip the redundant watermark
/// insert and still remove the orphans.
#[test]
fn repair_is_idempotent_when_watermark_already_covers_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-idempotent-watermark");
    let archive = unique_db_path("repair-idempotent-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = support::sample_receipt_with_keypair_and_timestamp(
                &format!("iw-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Simulate the partial-failure state in one write: co-archive the
        // claim-log for [1,2], delete ONLY their source rows (leaving the
        // orphaned claim-log rows), and record the watermark the botched rotation
        // stamped at boundary 2 before it crashed.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                copy_checkpoint_prefix_to_attached_archive(connection, 2)?;
                support::restore_transparency_projection_guards(connection)?;
                connection.execute_batch("DETACH DATABASE archive")?;
                // The ledger must name the real archive the botched rotation
                // co-archived [1,2] into, so the reopen's watermark check finds
                // the backing evidence.
                let canonical_archive_path = std::fs::canonicalize(&archive_path)?;
                let canonical_archive_path = canonical_archive_path.to_str().ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "canonical retention archive path is not valid UTF-8".to_string(),
                    )
                })?;
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection,
                    2,
                    100,
                    canonical_archive_path,
                    None,
                    1,
                )?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 2, "repair removes the orphaned claim-log rows");

    // The orphans are gone and the watermark still sits at the covered boundary.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(orphans, 0, "orphaned claim-log rows must be removed");
    let watermark: Option<i64> = live.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(watermark, Some(2), "the covering watermark is preserved");
    drop(live);
    drop(store);

    // Open starts the writer with a fail-closed, unseeded head. A flush is an
    // actor barrier: sample serving health only after retained-state validation.
    let reopened = SqliteReceiptStore::open(&path)?;
    reopened.flush_receipt_writes()?;
    let health = reopened.receipt_store_health()?;
    assert!(health.healthy, "repaired store must be healthy: {health:?}");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
