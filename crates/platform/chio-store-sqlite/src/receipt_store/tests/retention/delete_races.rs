//! Locked deletion preserves data when archival races a concurrent writer.

use super::*;

/// A dependent row that a second store handle commits into the archived prefix
/// AFTER the co-archival copy but BEFORE the delete transaction takes its write
/// lock must never be deleted un-archived. The delete re-checks co-archival
/// completeness under the BEGIN IMMEDIATE lock and fails closed, so the prefix
/// and the newly inserted row survive for a later rotation to re-copy.
#[test]
fn delete_fails_closed_when_a_dependent_row_escapes_the_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-delete");
    let archive = unique_db_path("toctou-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("toctou-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let receipt_id = super::super::support::first_tool_receipt_id(&store)?;

    // Co-archive the aged [1,2] prefix, then simulate a concurrent handle
    // committing a settlement reconciliation for a receipt in that prefix after
    // the copy has run, and only then attempt the delete.
    let fail_closed = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let receipt_id = receipt_id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            copy_archived_prefix(connection, 2)?;
            // The archive now faithfully holds [1,2]. A second writer commits a
            // dependent row into the archived prefix, unseen by the copy above.
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'settled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            let result = delete_archived_prefix_in_tx(connection, 2, 150, &archive_path, None, &crate::store_clock::StoreClock::new(chio_test_support::clock::clock()));
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(result.is_err())
        }
    })?;
    assert!(
        fail_closed,
        "the delete must fail closed when a dependent row is not in the archive"
    );

    // Fail-closed: the prefix and the un-archived reconciliation both survive.
    let live = store.reader_connection_for_test()?;
    let live_receipts: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_receipts, 2,
        "the archived prefix must survive the refusal"
    );
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_settlement, 1,
        "the un-archived reconciliation must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The archive-path pin is checked before the delete transaction takes the write
/// lock, so two store handles rotating concurrently to DIFFERENT archives can
/// split the prefix: one commits `[1, W1]` to archive A after the outer check,
/// then the other copies only the surviving suffix to archive B and records a
/// higher watermark naming B, leaving the ledger pointing at a file that lacks
/// the earlier prefix. The delete must re-read and re-enforce the ledger archive
/// path AFTER acquiring the write lock and fail closed, so the split is caught
/// and the surviving suffix is preserved for a later rotation.
#[test]
fn delete_rechecks_archive_path_under_the_write_lock() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-path-split");
    let archive_a = unique_db_path("toctou-path-split-a");
    let archive_b = unique_db_path("toctou-path-split-b");
    let archive_a_path = archive_a.to_str().ok_or("archive path invalid")?;
    let archive_b_path = archive_b.to_str().ok_or("archive path invalid")?;
    let keypair = super::super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::super::support::signer(&keypair, 2))?;
    // Two aged batches: [1,2] at timestamp 100, [3,4] at timestamp 200.
    for i in 0..2u64 {
        let r = super::super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 2..4u64 {
        let r = super::super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("b-{i}"),
            i + 1,
            200,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // A concurrent rotation commits [1,2] to archive A: the ledger now pins the
    // archive path to A and the live prefix [1,2] is gone.
    let first = store.archive_receipts_before(150, archive_a_path)?;
    assert_eq!(first, 2, "the aged [1,2] batch archives to A");

    // This rotation, in flight against a DIFFERENT archive B, has already copied
    // the surviving suffix [3,4] into B and now reaches its locked delete for
    // W=4. Under the write lock the ledger names A, so the delete must refuse the
    // path split rather than strand [1,2] in A behind a ledger pointing at B.
    let refusal = store.writer_handle().run_write({
        let archive_b_path = archive_b_path.to_string();
        move |connection| {
            let escaped = archive_b_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            copy_archived_prefix(connection, 4)?;
            let result = delete_archived_prefix_in_tx(
                connection,
                4,
                250,
                &archive_b_path,
                None,
                &crate::store_clock::StoreClock::new(chio_test_support::clock::clock()),
            );
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(result.err().map(|error| error.to_string()))
        }
    })?;
    let message = refusal
        .ok_or("the delete must fail closed when a concurrent rotation split the archive path")?;
    assert!(
        message.contains("differs from the archive"),
        "expected the archive-path pin to fire under the write lock, got: {message}"
    );

    // Fail-closed: the surviving [3,4] suffix is intact for a later rotation.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no [3,4] rows may be deleted when the locked path re-check rejects the split"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive_a);
    let _ = std::fs::remove_file(&archive_b);
    Ok(())
}
