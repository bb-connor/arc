//! Retention behavior tests (co-archive-and-delete, watermark, chain
//! exemption, size convergence, recovery).

use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{ReceiptStoreError, RetentionConfig};

use crate::SqliteReceiptStore;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "chio-{prefix}-{}-{nonce}.sqlite3",
        std::process::id()
    ))
}

#[test]
fn watermark_ledger_reports_max_and_rejects_regression() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{insert_receipt_retention_watermark, retention_watermark};
    let path = unique_db_path("watermark-ledger");
    let store = SqliteReceiptStore::open(&path)?;
    // A pristine store has never archived.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(retention_watermark(&connection)?, None);

    insert_receipt_retention_watermark(&connection, 10, 100, "archive.sqlite3", None, 1)?;
    insert_receipt_retention_watermark(&connection, 25, 200, "archive.sqlite3", None, 2)?;
    assert_eq!(retention_watermark(&connection)?, Some(25));

    // A rotation that would lower the watermark is rejected fail-closed.
    let regression =
        insert_receipt_retention_watermark(&connection, 20, 300, "archive.sqlite3", None, 3);
    let message = regression
        .err()
        .ok_or("expected RetentionWatermarkRegression")?
        .to_string();
    assert!(
        message.contains("retention watermark regression"),
        "unexpected error: {message}"
    );
    // The rejected write left the ledger unchanged.
    assert_eq!(retention_watermark(&connection)?, Some(25));

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn backfill_refuses_regeneration_over_checkpointed_range() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::support::validate_or_backfill_claim_receipt_log_entries;

    let path = unique_db_path("backfill-refuse");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let keypair = super::support::receipt_test_keypair();
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..2u64 {
            let receipt =
                super::support::sample_receipt_with_keypair(&format!("bf-{i}"), i + 1, &keypair);
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        // A checkpoint now covers [1, 2].
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
    }

    // Simulate a botched manual repair: empty the projection on a checkpointed
    // store by dropping the reject-delete guard and deleting the rows.
    let store = SqliteReceiptStore::open_existing(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM claim_receipt_log_entries;",
        )?;
        Ok(())
    })?;

    let connection = store.reader_connection_for_test()?;
    let error = validate_or_backfill_claim_receipt_log_entries(&connection, true);
    let message = error
        .err()
        .ok_or("expected ArchivedRangeProjection, backfill regenerated instead")?
        .to_string();
    assert!(
        message.contains("checkpointed or archived range"),
        "unexpected error: {message}"
    );
    // `chio receipt retention repair` only removes claim-log rows whose source
    // rows are already gone; with an empty projection it removes nothing and
    // leaves the store bricked, so the guidance must not point there. It must
    // name an applicable recovery instead.
    assert!(
        !message.contains("retention repair"),
        "must not point at the no-op retention repair for a missing projection: {message}"
    );
    assert!(
        message.contains("restore") && message.contains("backup"),
        "must direct operators to an applicable recovery path: {message}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Append two aged receipts (timestamp 100) checkpointed as [1,2] and four
/// fresh receipts (timestamp 500) checkpointed as [3,4] with 5..6 left
/// uncheckpointed, then genuinely archive the aged range so a real archive holds
/// the co-archived `[1, 2]` prefix and the live rows are deleted with the
/// watermark set to 2.
fn store_with_archived_first_checkpoint(
    path: &std::path::Path,
    archive_path: &str,
    keypair: &chio_core::crypto::Keypair,
) -> Result<SqliteReceiptStore, Box<dyn std::error::Error>> {
    let store = SqliteReceiptStore::open(path)?;
    store.enable_background_checkpoints(super::support::signer(keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ce-aged-{i}"),
            i + 1,
            100,
            keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    for i in 2..6u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ce-fresh-{i}"),
            i + 1,
            500,
            keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Archive only the aged first checkpoint's range [1,2]: the rows move to a
    // real archive, the live prefix is deleted, and the ledger records W=2.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2, "only the aged [1,2] batch archives");
    Ok(store)
}

#[test]
fn checkpoint_chain_watermark_exemption() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::verify_checkpoint_chain_integrity;

    let path = unique_db_path("chain-exemption");
    let archive = unique_db_path("chain-exemption-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // With the exemption the chain still verifies: checkpoint 1 (batch_end_seq
    // <= W = 2) skips the live Merkle rebuild and trusts the co-archived range;
    // checkpoint 2 (batch_end_seq 4 > W) is rebuilt as before.
    let connection = store.reader_connection_for_test()?;
    verify_checkpoint_chain_integrity(&connection)?;

    // Tamper with a claim-log row ABOVE the watermark: the chain must still
    // fail (the exemption never weakens verification above W).
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 3;",
        )?;
        Ok(())
    })?;
    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "tamper above the watermark must still fail the chain"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The watermark exemption must be backed by the archived evidence, not merely
/// by a matching checkpoint boundary and an absent live prefix. After a genuine
/// rotation the watermark is trusted, but once the archive that vouches for the
/// deleted prefix is gone the exemption is withdrawn fail-closed even though the
/// ledger and boundary are unchanged (the state an out-of-band prefix delete
/// plus a planted watermark would leave behind).
#[test]
fn watermark_trust_requires_backing_archive() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::trusted_retention_watermark;

    let path = unique_db_path("watermark-backing");
    let archive = unique_db_path("watermark-backing-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // Archive present and covering [1,2]: the watermark is trusted.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(trusted_retention_watermark(&connection)?, 2);
    drop(connection);

    // Remove the archive that backs the deleted prefix. The ledger row, the
    // matching checkpoint boundary, and the absent live prefix are all still in
    // place, but there is no longer any archived evidence to trust.
    std::fs::remove_file(&archive)?;
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "a watermark with no backing archive must not be trusted"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Co-archive-and-delete removes the source tables and the claim-log projection
/// together, so append, health, checkpoint status, and a fresh open() all
/// succeed after archival. (Deleting source rows while leaving the projection
/// behind would leave set drift that bricks the store on the next rotation.)
#[test]
fn retention_then_append_and_reopen_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-reopen");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("retention-reopen-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        // 4 aged receipts (old timestamps) get two checkpoints [1,2],[3,4];
        // 2 fresh receipts stay uncheckpointed and unaged.
        for i in 0..4u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("aged-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(2)?.is_some());

        // Archive everything older than timestamp 150 (all four aged rows).
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the two checkpointed aged batches archive");

        // The store is NOT bricked: append, health, and checkpoint status all
        // succeed AFTER archival.
        let fresh =
            super::support::sample_receipt_with_keypair_and_timestamp("fresh-0", 5, 500, &keypair);
        store.append_chio_receipt_returning_seq(&fresh)?;
        store.flush_receipt_writes()?;
        assert!(
            store.receipt_store_health()?.healthy,
            "store healthy post-archival"
        );
        assert!(store.receipt_checkpoint_status(Some(1))?.healthy);
    }

    // And a fresh open() succeeds (open-time seed runs the full verifier and
    // the watermark-aware chain walk against the co-archived range).
    let reopened = SqliteReceiptStore::open(&path)?;
    let more =
        super::support::sample_receipt_with_keypair_and_timestamp("fresh-1", 6, 600, &keypair);
    reopened.append_chio_receipt_returning_seq(&more)?;
    reopened.flush_receipt_writes()?;
    assert!(reopened.receipt_store_health()?.healthy);

    // The archived and live receipt-id sets partition the history with no
    // overlap: the four aged ids are gone from live, present in the archive.
    // The archive is a minimal evidence bundle (no live-only tables), so it is
    // consumed with open() (which rebuilds the checkpoint projections from the
    // co-archived kernel_checkpoints), not open_existing().
    let archive_store = SqliteReceiptStore::open(&archive)?;
    assert_eq!(archive_store.tool_receipt_count()?, 4);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A rotation must dispatch to the writer actor, never begin a write
/// transaction on a reader-pool connection (mirrors single_writer.rs
/// `reader_pool_never_begins_a_write_transaction`).
#[test]
fn reader_pool_never_rotates() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("reader-never-rotates");
    let store = SqliteReceiptStore::open(&path)?;
    // A rotation over an empty store is a no-op but still routes through the
    // &self -> Rotate-command path to the single writer.
    let archived = store.rotate_if_needed(&RetentionConfig::default())?;
    assert_eq!(archived, 0);
    // Pin a reader-pool connection read-only: it can never open the IMMEDIATE
    // (write) transaction the co-archive-and-delete needs, so retention could
    // only have executed on the writer actor.
    let reader = store.reader_connection_for_test()?;
    reader.execute_batch("PRAGMA query_only = ON;")?;
    let write_attempt = reader.execute("CREATE TABLE reader_probe (x INTEGER)", []);
    assert!(
        write_attempt.is_err(),
        "reader-pool connections must be read-only (retention runs on the writer)"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// The retention watermark ledger is security-load-bearing (chain verification
/// trusts W to skip claim-log validation), so its append-only, strictly
/// monotonic guarantee is enforced by DB triggers, not only by the insert
/// helper. A raw UPDATE, a raw DELETE, and a non-monotonic INSERT are all
/// rejected by the database.
#[test]
fn watermark_ledger_db_triggers_reject_tamper() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::insert_receipt_retention_watermark;
    let path = unique_db_path("watermark-triggers");
    let store = SqliteReceiptStore::open(&path)?;
    let connection = store.reader_connection_for_test()?;

    // Seed a legitimate mark through the helper (the trigger allows the first
    // strictly-increasing insert).
    insert_receipt_retention_watermark(&connection, 10, 100, "archive.sqlite3", None, 1)?;

    // A raw UPDATE is rejected by receipt_retention_watermark_reject_update.
    let updated = connection.execute(
        "UPDATE receipt_retention_watermark SET archived_through_entry_seq = 999",
        [],
    );
    assert!(
        updated.is_err(),
        "raw UPDATE of the watermark must be rejected"
    );

    // A raw DELETE is rejected by receipt_retention_watermark_reject_delete.
    let deleted = connection.execute("DELETE FROM receipt_retention_watermark", []);
    assert!(
        deleted.is_err(),
        "raw DELETE of the watermark must be rejected"
    );

    // A non-monotonic raw INSERT (equal to the current MAX) is rejected by
    // receipt_retention_watermark_reject_regression, even though it bypasses the
    // insert helper's own regression check.
    let equal = connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, rotated_at) \
         VALUES (10, 200, 'archive.sqlite3', NULL, 2)",
        [],
    );
    assert!(
        equal.is_err(),
        "a non-increasing raw INSERT must be rejected"
    );

    // A lower raw INSERT is likewise rejected.
    let lower = connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, rotated_at) \
         VALUES (5, 300, 'archive.sqlite3', NULL, 3)",
        [],
    );
    assert!(lower.is_err(), "a regressing raw INSERT must be rejected");

    // The ledger is unchanged: still exactly the one legitimate mark of 10.
    let (count, max_seq): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(archived_through_entry_seq), 0) FROM receipt_retention_watermark",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(count, 1);
    assert_eq!(max_seq, 10);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn tenant_scoped_rotation_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("tenant-rejected");
    let store = SqliteReceiptStore::open(&path)?;
    let config = RetentionConfig {
        tenant_id: Some("tenant-a".to_string()),
        ..RetentionConfig::default()
    };
    let error = store.rotate_if_needed(&config);
    let message = error
        .err()
        .ok_or("expected RetentionTenantScopeUnsupported")?
        .to_string();
    assert!(
        message.contains("tenant-scoped retention"),
        "unexpected: {message}"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn settlement_and_metered_rows_are_archived_not_cascaded() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("recon-archived");
    let archive = unique_db_path("recon-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("recon-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Attach a settlement + metered reconciliation row, and an authorization
    // consumption row, to the first receipt. All three sit in the archived
    // range (entry_seq <= W) because the receipt itself does.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'settled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-1', 1, 1, 'usd', NULL, 1, 'reconciled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            // chio_authorization_receipt_consumptions.authorization_receipt_id
            // is FK REFERENCES chio_tool_receipts(receipt_id), so it must name
            // an existing receipt; consumer_receipt_id/request_id/session_id/
            // tool_call_id/parameter_hash carry no FK, so arbitrary values
            // satisfy their NOT NULL constraints.
            connection.execute(
                "INSERT INTO chio_authorization_receipt_consumptions \
                 (authorization_receipt_id, consumer_receipt_id, request_id, session_id, tool_call_id, tenant_id, parameter_hash, consumed_at_unix_ms) \
                 VALUES (?1, 'consumer-recon-0', 'req-recon-0', 'sess-recon-0', 'tool-call-recon-0', NULL, 'hash-recon-0', 1000)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2);

    // Gone from live, present in the archive (co-archived, not cascaded away).
    let live = store.reader_connection_for_test()?;
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_settlement, 0, "settlement row absent from live");
    let live_metered: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_metered, 0, "metered row absent from live");
    let live_consumptions: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_consumptions, 0, "consumption row absent from live");
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let arch_settlement: i64 = arch.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    let arch_metered: i64 = arch.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations",
        [],
        |row| row.get(0),
    )?;
    let arch_consumptions: i64 = arch.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(arch_settlement, 1, "settlement row co-archived");
    assert_eq!(arch_metered, 1, "metered row co-archived");
    assert_eq!(arch_consumptions, 1, "consumption row co-archived");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn size_rotation_converges_below_threshold() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("size-converges");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("size-archive");
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
    for i in 0..64u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sz-{i}"),
            i + 1,
            100 + i,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // Force the size branch: threshold just under the current live size.
    let before = store.live_db_size_bytes()?;
    let config = RetentionConfig {
        retention_days: u64::MAX, // disable the time branch
        max_size_bytes: before.saturating_sub(1),
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    let archived = store.rotate_if_needed(&config)?;
    assert!(archived > 0, "size trigger archived a checkpointed prefix");

    // After incremental_vacuum the live measured size drops below the
    // threshold, so a second rotation with the SAME config is a no-op (the
    // trigger converged, it did not re-fire).
    let after = store.live_db_size_bytes()?;
    assert!(
        after < before,
        "live size shrank after rotation ({after} < {before})"
    );
    let again = store.rotate_if_needed(&config)?;
    // Either the size is already below the (updated) threshold, or the only
    // remaining rows are uncheckpointed so W stays put: no runaway loop.
    assert!(again == 0 || store.live_db_size_bytes()? <= after);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Size-driven rotation must still make progress when many receipts share the
/// median timestamp (second-resolution or bursty traffic). A cutoff exactly at
/// the shared median blocks every checkpoint batch that contains a row at the
/// median, so the median cutoff must clear the shared timestamp; otherwise the
/// size trigger archives nothing and the DB never shrinks below the threshold.
#[test]
fn size_rotation_archives_when_median_timestamp_is_shared() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("size-shared-median");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("size-shared-median-archive");
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
    // Every receipt carries the SAME timestamp, so the median equals it too.
    for i in 0..64u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sm-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let before = store.live_db_size_bytes()?;
    let config = RetentionConfig {
        retention_days: u64::MAX, // disable the time branch
        max_size_bytes: before.saturating_sub(1),
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    let archived = store.rotate_if_needed(&config)?;
    assert!(
        archived > 0,
        "size rotation must archive a checkpointed prefix even when the median timestamp is shared"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention triggers must age out CHILD-receipt evidence too. The threshold
/// resolver reads the claim receipt log, which projects both tool and child
/// receipts, not chio_tool_receipts alone; otherwise a store whose evidence is
/// child-only sees an empty tool table and never crosses the time trigger, so
/// aged child receipts would be retained forever even though the rotation path
/// co-archives child rows once a cutoff is chosen.
#[test]
fn child_only_evidence_ages_out_under_time_trigger() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-child-only");
    let archive = unique_db_path("retention-child-only-archive");
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two aged child receipts and NO tool receipts. Their claim-log entries form
    // a checkpointed batch far past any retention window.
    for i in 0..2u64 {
        let child = super::support::sample_child_receipt_with_keypair_and_timestamp(
            &format!("aged-child-{i}"),
            100,
            &keypair,
        );
        store.append_child_receipt_record(&child)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "the child-only prefix must be checkpointed before it can be archived"
    );

    let before = store.reader_connection_for_test()?;
    let tool_rows: i64 =
        before.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(tool_rows, 0, "the store holds child receipts only");
    let child_rows: i64 =
        before.query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(child_rows, 2, "two child receipts are live before rotation");

    // Time-driven rotation: the timestamp-100 receipts are far past a one-day
    // window; the size branch is disabled.
    let config = RetentionConfig {
        retention_days: 1,
        max_size_bytes: u64::MAX,
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    store.rotate_if_needed(&config)?;

    // The aged child prefix aged out. rotate_if_needed reports tool rows archived
    // (zero here), so assert directly on the live child rows.
    let after = store.reader_connection_for_test()?;
    let live_child: i64 =
        after.query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(
        live_child, 0,
        "aged child-only evidence must age out under the time trigger"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The time and size triggers are independent: a store over its size limit must
/// still rotate even when the age cutoff would archive nothing. A checkpoint ages
/// out only when its ENTIRE prefix is older than the cutoff, so a still-fresh
/// receipt at the head of the prefix blocks the age cutoff for every batch.
/// Resolving that no-op age cutoff and returning before the size check would
/// leave an oversized store oversized forever; the size cutoff must apply on the
/// same pass.
#[test]
fn size_trigger_applies_when_time_cutoff_is_a_noop() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-size-fallthrough");
    let archive = unique_db_path("retention-size-fallthrough-archive");
    let keypair = super::support::receipt_test_keypair();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // entry_seq -> timestamp. Entry 1 is still inside the 10-day window, so it
    // blocks the age cutoff for the whole prefix; entry 2 is well aged, so the
    // time trigger still fires. Entry 4 is brand new, so the median+1 size cutoff
    // frees only the first checkpoint batch [1,2], not [3,4].
    let timestamps = [
        now.saturating_sub(500_000),
        now.saturating_sub(2_000_000),
        now.saturating_sub(100_000),
        now,
    ];
    for (i, ts) in timestamps.iter().enumerate() {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("fallthrough-{i}"),
            (i + 1) as u64,
            *ts,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(2)?.is_some(),
        "both checkpoint batches must be persisted before rotation"
    );

    // Time trigger fires (entry 2 is well past the 10-day window) but its cutoff
    // archives nothing (entry 1 is still fresh at the head of the prefix). The
    // store is over the size limit, so the size cutoff must free the first aged
    // checkpoint batch on the same pass.
    let config = RetentionConfig {
        retention_days: 10,
        max_size_bytes: 1,
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    let archived = store.rotate_if_needed(&config)?;
    assert_eq!(
        archived, 2,
        "the size cutoff must free the first checkpoint batch even though the age cutoff is a no-op"
    );

    let after = store.reader_connection_for_test()?;
    let live_tool: i64 = after.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "the aged first batch was archived and deleted; the fresh batch stayed live"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Rotation deletes evidence, so it must run on a verified chain. A store opened
/// with `incremental_verification = false` seeds its writer head via the cheap
/// `seed_head_snapshot`, which defers the full claim-log and checkpoint-chain
/// audit to the next append, so a Verified head is NOT proof of integrity in that
/// mode. A corrupt projection must make the rotation fail closed and delete
/// nothing, rather than archive-and-delete against an unaudited log.
#[test]
fn non_incremental_rotation_validates_chain_before_deleting(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-nonincremental-validate");
    let archive = unique_db_path("retention-nonincremental-validate-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a checkpointed prefix at timestamp 100 (older than the cutoff below).
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        let mut first_id = String::new();
        for i in 0..2u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("nonincr-{i}"),
                i + 1,
                100,
                &keypair,
            );
            if i == 0 {
                first_id = receipt.id.clone();
            }
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(
            store.load_checkpoint_by_seq(1)?.is_some(),
            "the prefix must be checkpointed so a rotation would otherwise archive it"
        );
        first_id
    };

    // Reopen with incremental_verification = false: the writer head is seeded via
    // the cheap snapshot without auditing the claim log.
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Corrupt a claim-log projection row. The snapshot seed never inspects it, so
    // only the full pre-rotation verification catches this.
    super::support::tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });

    // Rotation must fail closed on the corrupt chain rather than archive-and-delete.
    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or(
            "rotation on a corrupt non-incremental chain must fail closed, not archive-and-delete",
        )?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the pre-rotation verification, got {error:?}"
    );

    // Fail-closed: nothing was deleted; the live evidence is intact.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "no evidence may be deleted when the chain is unverified"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no claim-log rows may be deleted when the chain is unverified"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Rotation deletes evidence, so it must never run against a claim-log
/// projection that has already drifted from its source rows - even on an
/// incremental store, whose per-append verified head never re-checks a
/// retroactive source-row deletion. A store in the drift shape (source receipts
/// deleted, orphaned claim-log rows left behind) must make the rotation fail
/// closed and delete nothing, rather than co-archive the orphans without their
/// receipts and then delete the live claim log, destroying the evidence
/// `retention_repair` needs to recover.
#[test]
fn incremental_rotation_rejects_projection_drift() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("incremental-drift-rotation");
    let archive = unique_db_path("incremental-drift-rotation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // A default open() store runs incremental verification, so the pre-rotation
    // checkpoint audit is skipped; only the projection audit can catch the drift.
    let store = SqliteReceiptStore::open(&path)?;
    assert!(store.incremental_verification_enabled());
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("id-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;

    // Fabricate the drift shape on the same live instance: co-archive the
    // claim-log for [1,2] and delete ONLY their source rows, leaving orphaned
    // claim-log rows. The incremental head stays Verified because it never
    // re-audits the retroactive source deletion.
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
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(())
        }
    })?;

    // The rotation must detect the projection drift and fail closed BEFORE any
    // archive-and-delete.
    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or("rotation over a drifted projection must fail closed, not archive-and-delete")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the projection audit, got {error:?}"
    );

    // Fail-closed: the orphaned claim-log rows survive, so repair can still run.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned claim-log rows must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store reopened through `open_existing` holds READ_WRITE-without-CREATE
/// connection flags so that a missing main database fails closed. Because
/// `ATTACH DATABASE` inherits those flags, the first retention rotation against
/// such a store must still create its not-yet-existing sibling archive rather
/// than fail on the ATTACH. The rotation materializes the archive with CREATE
/// permission before attaching it, so the first rotation succeeds and the
/// archive appears.
#[test]
fn first_rotation_creates_archive_on_open_existing_store() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("open-existing-first-rotation");
    let archive = unique_db_path("open-existing-first-rotation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a store with a fully checkpointed prefix that will age past the
    // cutoff, then close it so the reopen exercises the open_existing flags.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("first-rotation-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(
            store.load_checkpoint_by_seq(1)?.is_some(),
            "the prefix must be checkpointed so the rotation has something to archive"
        );
    }

    // The first rotation is responsible for creating the archive; it must not
    // exist yet.
    assert!(
        !archive.exists(),
        "the archive must be absent before the first rotation"
    );

    // Reopen through open_existing (READ_WRITE without CREATE). Without the
    // pre-ATTACH archive creation the rotation fails here: the inherited
    // no-CREATE flags cannot create the sibling archive at ATTACH time.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 4,
        "the aged checkpointed prefix archives on the first rotation"
    );
    assert!(
        archive.exists(),
        "the first rotation created the sibling archive database"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Rotation co-archives evidence and then deletes the live prefix, so it must
/// refuse a non-durable or self-aliasing archive target. An in-memory database
/// is destroyed on DETACH, and a path that aliases the live database makes
/// SQLite attach the live file itself; either way the delete would remove the
/// only copy of the archived evidence while still recording a watermark. The
/// rotation must fail closed and delete nothing.
#[test]
fn rotation_rejects_non_durable_or_aliasing_archive_path() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("nondurable-archive");
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("nd-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;

    // An in-memory archive target is destroyed on DETACH: the rotation must
    // reject it before archiving-and-deleting the live prefix.
    let memory_error = store
        .archive_receipts_before(150, ":memory:")
        .err()
        .ok_or("rotation into an in-memory archive must fail closed")?;
    assert!(
        matches!(memory_error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict over a non-durable archive, got {memory_error:?}"
    );

    // An archive path that aliases the live database is rejected the same way:
    // attaching the live file as `archive` would let the delete destroy the only
    // copy.
    let live_path = path.to_str().ok_or("db path invalid")?;
    let alias_error = store
        .archive_receipts_before(150, live_path)
        .err()
        .ok_or("rotation into a self-aliasing archive must fail closed")?;
    assert!(
        matches!(alias_error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict over a self-aliasing archive, got {alias_error:?}"
    );

    // Fail-closed: no evidence was deleted; the live prefix is intact.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 4,
        "no receipts may be deleted on a rejected archive target"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 4,
        "no claim-log rows may be deleted on a rejected archive target"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A rotation is an in-flight writer, so `dispatch_rotate` increments
/// `writer.inflight` before sending the Rotate
/// command and the actor's Rotate arm must decrement it on dequeue. Without the
/// decrement the counter leaks and `receipt_store_health().writer.inflight`
/// would report a permanently in-flight writer after any rotation.
#[test]
fn rotate_does_not_leak_inflight() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotate-inflight");
    let archive = unique_db_path("rotate-inflight-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("inflight-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Baseline: with every append drained, no writer is in flight.
    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "baseline inflight must be zero after flush"
    );

    // A successful archival (two checkpointed batches age past the cutoff).
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the aged checkpointed prefix archives");

    // The rotation released its in-flight slot: the counter is back to baseline,
    // not permanently incremented.
    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "a successful rotation must not leak an in-flight writer"
    );

    // A no-op rotation (nothing new to archive) also balances the counter.
    let again = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(again, 0, "re-archiving the same aged prefix is a no-op");
    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "a no-op rotation must not leak an in-flight writer either"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Watermark-aware chain verification skips the live Merkle rebuild for
/// checkpoints with `batch_end_seq <= W`, trusting
/// W from the retention ledger. The ledger's DB triggers enforce monotonicity
/// ONLY, not that W is a genuine archived-checkpoint boundary, so a forged,
/// strictly-larger W (past the latest real checkpoint) must NOT disable
/// verification for never-archived live ranges. W is trusted as a skip
/// exemption only when it matches a persisted checkpoint boundary; otherwise
/// verification falls back to a full rebuild (fail-closed).
#[test]
fn bogus_watermark_does_not_skip_verification() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{
        insert_receipt_retention_watermark, verify_checkpoint_chain_integrity,
    };

    let path = unique_db_path("bogus-watermark");
    let store = SqliteReceiptStore::open(&path)?;
    let keypair = super::support::receipt_test_keypair();
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two checkpoints cover [1,2] and [3,4]; NOTHING is archived (every
    // claim-log row is still live), so honest verification fully rebuilds.
    for i in 0..4u64 {
        let receipt =
            super::support::sample_receipt_with_keypair(&format!("bw-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Forge a strictly-larger-but-bogus watermark: W = 100 is far beyond the
    // latest real checkpoint boundary (4) and matches no kernel_checkpoints
    // batch_end_seq. The monotonic-only ledger trigger accepts the first insert.
    store.writer_handle().run_write(|connection| {
        insert_receipt_retention_watermark(connection, 100, 100, "bogus-archive.sqlite3", None, 1)?;
        Ok(())
    })?;

    // Tamper a live claim-log row inside checkpoint 1's range [1,2]. The Merkle
    // rebuild for checkpoint 1 would now fail if (and only if) it actually runs.
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 1;",
        )?;
        Ok(())
    })?;

    // Fail-closed: because the bogus W does not correspond to a real archived
    // checkpoint boundary, verification must NOT skip the [1,2] range; it
    // rebuilds and catches the tamper. Trusting the bogus W would skip both
    // checkpoints and wrongly pass.
    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "a bogus watermark must not disable Merkle verification for un-archived ranges"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// The co-archival completeness check must verify each archived table by
/// IDENTITY, not row-count. If the archive
/// file already holds a stale/conflicting row for a receipt in the archived
/// prefix (different bytes), the idempotent `INSERT OR IGNORE` copy keeps the
/// stale row and drops the live one, so a count-only check would pass while the
/// archived bytes diverge. Verification must FAIL fail-closed before any delete,
/// leaving the live rows intact.
#[test]
fn co_archival_rejects_conflicting_stale_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-conflict");
    let archive = unique_db_path("co-archival-conflict-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("conflict-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Pre-seed the archive file with a STALE, conflicting claim-log row for the
    // archived prefix: the same entry_seq (PK) as a live row that will be
    // archived, but with different bytes and a different receipt_id. The
    // rotation's `INSERT OR IGNORE` copy keeps this stale row (PK collision) and
    // drops the faithful live row, so a count-only co-archival check would pass
    // while the archived bytes diverge.
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            r#"
            CREATE TABLE claim_receipt_log_entries (
                entry_seq INTEGER PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL,
                source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL,
                capability_id TEXT, session_id TEXT, parent_request_id TEXT,
                request_id TEXT, subject_key TEXT, issuer_key TEXT,
                tool_server TEXT, tool_name TEXT, raw_json TEXT NOT NULL
            );
            "#,
        )?;
        seed.execute(
            "INSERT INTO claim_receipt_log_entries \
             (entry_seq, receipt_id, receipt_kind, source_seq, timestamp, raw_json) \
             VALUES (1, 'stale-conflict-id', 'tool_receipt', 1, 100, '{\"stale\":true}')",
            [],
        )?;
    }

    // Rotate: the co-archival identity check must reject the divergent archive
    // and abort fail-closed BEFORE any delete.
    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or(
            "expected RetentionArchiveIncomplete; rotation succeeded over a conflicting archive",
        )?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );

    // The live rows are intact: the abort happened before the delete.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no live claim-log rows deleted when co-archival verify fails"
    );
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when co-archival verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Co-archival must verify capability lineage by identity too. The delete
/// removes the archived receipts but leaves the live lineage rows, so the
/// archive becomes the only standalone copy of those receipts' subject/issuer/
/// grants. A reused archive holding the same capability_id under divergent
/// lineage bytes is kept by the idempotent `INSERT OR IGNORE` copy, so a
/// count-only check would pass while the archived attribution diverges.
/// Verification must FAIL fail-closed before any delete.
#[test]
fn co_archival_rejects_conflicting_capability_lineage() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-cap-lineage");
    let archive = unique_db_path("co-archival-cap-lineage-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("cl-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // The sample receipts all carry capability_id "cap-1"; give it a live
    // lineage row so the co-archival copy has an attribution row to archive.
    store.writer_handle().run_write(|connection| {
        connection.execute(
            "INSERT INTO capability_lineage \
             (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id) \
             VALUES ('cap-1', 'subject-live', 'issuer-live', 1, 100, '[]', 0, NULL)",
            [],
        )?;
        Ok(())
    })?;

    // Pre-seed the archive with a CONFLICTING lineage row for the same
    // capability_id but divergent identity bytes. The rotation's INSERT OR
    // IGNORE copy keeps this stale row, so without an identity check the delete
    // would proceed and the standalone archive would misattribute the receipts.
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            r#"
            CREATE TABLE capability_lineage (
                capability_id TEXT PRIMARY KEY, subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL, issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0, parent_capability_id TEXT
            );
            "#,
        )?;
        seed.execute(
            "INSERT INTO capability_lineage \
             (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id) \
             VALUES ('cap-1', 'subject-stale', 'issuer-stale', 1, 100, '[]', 0, NULL)",
            [],
        )?;
    }

    // Rotate: the capability-lineage identity check must reject the divergent
    // archive and abort fail-closed BEFORE any delete.
    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete over a conflicting capability lineage")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete for capability_lineage"),
        "unexpected error: {message}"
    );

    // The live receipts are intact: the abort happened before any delete.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when capability-lineage verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The operator recovery path (`chio receipt retention repair --archive`): a
/// store bricked by source rows deleted with the claim-log projection rows left
/// behind can be repaired back to a writable, reopenable, healthy store.
#[test]
fn bricked_store_repair_restores_append() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("bricked-repair");
    let archive = unique_db_path("bricked-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a bricked store: archive + delete the source rows for a
    // checkpointed range but LEAVE the claim-log rows (the set-drift shape),
    // and copy the claim-log rows into the archive so repair can validate them.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("br-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Fabricate the bricked state: co-archive the claim-log for [1,2] into
        // the archive, then delete ONLY the source rows in live (leaving the
        // claim-log rows -> set drift).
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
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // The store is bricked: open() fails with set drift.
    assert!(
        SqliteReceiptStore::open(&path).is_err(),
        "store should be bricked pre-repair"
    );

    // Repair via open_existing (skips backfill), then append + open succeed.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert!(removed > 0, "repair removed the extra claim-log rows");
    drop(store);

    let repaired = SqliteReceiptStore::open(&path)?;
    let r =
        super::support::sample_receipt_with_keypair_and_timestamp("after-repair", 9, 900, &keypair);
    repaired.append_chio_receipt_returning_seq(&r)?;
    repaired.flush_receipt_writes()?;
    assert!(repaired.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store created before the retention migration and bricked by old deletes
/// has no watermark ledger, and repair opens it via `open_existing` (which does
/// not run the writable open() migration). Repair must create the ledger before
/// recording the repair watermark; otherwise the watermark insert fails on a
/// missing table, rolls the whole repair transaction back, and leaves the
/// legacy store unrepaired.
#[test]
fn repair_creates_missing_watermark_ledger_on_legacy_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("legacy-repair-watermark");
    let archive = unique_db_path("legacy-repair-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("lg-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Fabricate a legacy bricked state: co-archive the claim-log for [1,2],
        // delete only the source rows (set drift), AND drop the watermark ledger
        // so the store looks like it predates the retention migration.
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
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     DROP TABLE IF EXISTS receipt_retention_watermark;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // Repair via open_existing (skips backfill). Without the ledger creation the
    // watermark insert fails with "no such table: receipt_retention_watermark".
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert!(removed > 0, "repair removed the extra claim-log rows");
    drop(store);

    // The repair recorded a watermark and the store reopens healthy.
    let repaired = SqliteReceiptStore::open(&path)?;
    assert!(repaired.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Co-archival identity must pin the receipt-table primary key `seq`, not just
/// `receipt_id` + `raw_json`. The projection's `source_seq` (copied verbatim)
/// points at that `seq`, so an archive that already holds the same receipt under
/// a DIFFERENT `seq` (the idempotent copy keeps it on the `receipt_id` UNIQUE
/// conflict) would leave the archived projection pointing at the wrong source
/// row. Verification must FAIL fail-closed before any delete.
#[test]
fn co_archival_rejects_reused_seq_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-reused-seq");
    let archive = unique_db_path("co-archival-reused-seq-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("reused-seq-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Read the true bytes of the first receipt (seq 1), then pre-seed the archive
    // with that receipt under a DIVERGENT primary-key `seq`. The rotation's
    // INSERT OR IGNORE copy keeps this row on the receipt_id UNIQUE conflict, so
    // a receipt_id+raw_json-only check would pass while source_seq points nowhere.
    let (receipt_id, raw_json): (String, String) = {
        let live = store.reader_connection_for_test()?;
        live.query_row(
            "SELECT receipt_id, raw_json FROM chio_tool_receipts WHERE seq = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
    };
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            "CREATE TABLE chio_tool_receipts (\
                seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL, \
                capability_id TEXT NOT NULL, subject_key TEXT, issuer_key TEXT, grant_index INTEGER, \
                tool_server TEXT NOT NULL, tool_name TEXT NOT NULL, decision_kind TEXT NOT NULL, \
                policy_hash TEXT NOT NULL, content_hash TEXT NOT NULL, raw_json TEXT NOT NULL, tenant_id TEXT);",
        )?;
        seed.execute(
            "INSERT INTO chio_tool_receipts \
             (seq, receipt_id, timestamp, capability_id, tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES (9001, ?1, 100, 'cap', 'srv', 'tool', 'allow', 'ph', 'ch', ?2)",
            rusqlite::params![receipt_id, raw_json],
        )?;
    }

    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete; rotation accepted a reused-seq archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("chio_tool_receipts"),
        "the seq mismatch must fail the tool-receipt identity check: {message}"
    );

    // Fail-closed: the abort happened before any delete, so live rows are intact.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when co-archival verify fails"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "claim-log intact when co-archival verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Co-archival identity must cover the FULL receipt row, not just
/// `seq`/`receipt_id`/`raw_json`. Archive reads filter on the indexed/attribution
/// columns (`subject_key`, `issuer_key`, `grant_index`, `tenant_id`), so a reused
/// archive whose row matches those three columns but diverges on an attribution
/// column would misattribute the retained receipt once the live row is deleted.
/// Verification must FAIL fail-closed before any delete.
#[test]
fn co_archival_rejects_divergent_attribution_columns() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-attribution");
    let archive = unique_db_path("co-archival-attribution-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("attr-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Pre-seed the archive with a copy of the true seq-1 receipt that is byte
    // identical on every column EXCEPT `subject_key`. Copying from the live DB
    // (naming columns, not `SELECT *`) keeps seq/receipt_id/raw_json exactly
    // equal to live; only the attribution column is then tampered. The rotation's
    // INSERT OR IGNORE copy keeps this row on the seq primary-key conflict, so a
    // seq/receipt_id/raw_json-only check would pass while the archived attribution
    // silently diverges from the receipt being deleted.
    {
        let live_path = path.to_str().ok_or("db path invalid")?.replace('\'', "''");
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(&format!("ATTACH DATABASE '{live_path}' AS live;"))?;
        seed.execute_batch(
            "CREATE TABLE chio_tool_receipts (\
                seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL, \
                capability_id TEXT NOT NULL, subject_key TEXT, issuer_key TEXT, grant_index INTEGER, \
                tool_server TEXT NOT NULL, tool_name TEXT NOT NULL, decision_kind TEXT NOT NULL, \
                policy_hash TEXT NOT NULL, content_hash TEXT NOT NULL, raw_json TEXT NOT NULL, tenant_id TEXT);",
        )?;
        seed.execute_batch(
            "INSERT INTO chio_tool_receipts \
             (seq, receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, \
              tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json, tenant_id) \
             SELECT seq, receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, \
              tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json, tenant_id \
             FROM live.chio_tool_receipts WHERE seq = 1;",
        )?;
        // Tamper ONLY the attribution: a value guaranteed to differ from the live
        // subject_key whether that was NULL or a real key.
        seed.execute(
            "UPDATE chio_tool_receipts SET subject_key = 'tampered-attribution-' || COALESCE(subject_key, '') WHERE seq = 1",
            [],
        )?;
        seed.execute_batch("DETACH DATABASE live;")?;
    }

    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete; rotation accepted a divergent-attribution archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("chio_tool_receipts"),
        "the attribution mismatch must fail the tool-receipt identity check: {message}"
    );

    // Fail-closed: the abort happened before any delete, so live rows are intact
    // with their true attribution.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when co-archival verify fails"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "claim-log intact when co-archival verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair must validate the archived copy by IDENTITY before deleting
/// the orphaned live claim-log row, not merely by `receipt_id` presence. A reused
/// or wrong archive that carries the receipt under a divergent `source_seq` (or
/// any other column) would otherwise pass, and deleting the live row would leave
/// no faithful archived evidence behind.
#[test]
fn repair_rejects_divergent_archive_identity() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-divergent-archive");
    let archive = unique_db_path("repair-divergent-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("dv-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Fabricate the bricked state, but co-archive a DIVERGENT projection: same
        // receipt_id and entry_seq, wrong source_seq. Then delete the source rows
        // for [1,2], leaving orphaned claim-log rows.
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
                       (entry_seq, receipt_id, receipt_kind, source_seq, timestamp, capability_id, session_id, \
                        parent_request_id, request_id, subject_key, issuer_key, tool_server, tool_name, raw_json) \
                       SELECT entry_seq, receipt_id, receipt_kind, source_seq + 500, timestamp, capability_id, session_id, \
                        parent_request_id, request_id, subject_key, issuer_key, tool_server, tool_name, raw_json \
                       FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete; repair trusted a divergent archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );

    // Fail-closed: the orphaned rows survive, so no faithful evidence was lost.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned claim-log rows must survive a rejected repair"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair rounds the watermark up to a checkpoint boundary. When the
/// orphaned rows cover only PART of that batch, the rows above them may still
/// have live source receipts; stamping the watermark there would mark them
/// archived and skip their Merkle rebuild forever. Repair must refuse a partial
/// batch fail-closed.
#[test]
fn repair_refuses_partial_checkpoint_batch() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-partial-batch");
    let archive = unique_db_path("repair-partial-batch-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        // One checkpoint covers the whole batch [1,4] (max_batch 4).
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("pb-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        assert!(
            store.load_checkpoint_by_seq(2)?.is_none(),
            "one batch [1,4]"
        );
        // Orphan ONLY rows 1..=2 (co-archive faithfully, delete their source
        // rows), leaving rows 3..=4 with live source receipts inside the same
        // checkpoint batch.
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
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected a partial-batch refusal; repair watermarked live rows")?
        .to_string();
    assert!(
        message.contains("partially archived batch"),
        "unexpected error: {message}"
    );

    // Fail-closed: no watermark was recorded and the orphans survive.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned claim-log rows must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair stamps a checkpoint-aligned watermark that trusts the whole
/// [1, rounded] prefix as archived and skips its Merkle rebuild. Verifying only
/// the surviving orphaned rows is not enough: a botched rotation may also have
/// deleted some projection rows in that prefix outright, and if the archive
/// never held them the repair would seal an incomplete archive behind a trusted
/// watermark. Repair must verify a faithful archive row for every entry in the
/// prefix and refuse otherwise.
#[test]
fn repair_refuses_incomplete_prefix_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-incomplete-prefix");
    let archive = unique_db_path("repair-incomplete-prefix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        // One checkpoint covers the whole batch [1,4] (max_batch 4), so the
        // repair rounds up to boundary 4.
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("ip-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Fabricate a damaged store: archive ONLY the claim-log rows [3,4]
        // faithfully and orphan them (delete their source rows), while rows [1,2]
        // are deleted OUTRIGHT from both source AND projection and never archived.
        // The surviving orphans [3,4] pass the per-extra identity check, but the
        // prefix [1,4] the boundary would seal is missing [1,2] in the archive.
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
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq IN (3, 4); \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 4; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim_receipt_log_entries is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected an incomplete-archive refusal; repair sealed a partial archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("claim_receipt_log_entries"),
        "the missing prefix rows must fail the claim-log completeness check: {message}"
    );

    // Fail-closed: no watermark was recorded and the surviving orphans remain.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "surviving orphan rows must remain after the refusal"
    );
    let watermark: Option<i64> = live.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(
        watermark, None,
        "no watermark may be stamped over an incomplete archive"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

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
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
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
                connection.execute_batch("DETACH DATABASE archive")?;
                // The ledger must name the real archive the botched rotation
                // co-archived [1,2] into, so the reopen's watermark check finds
                // the backing evidence.
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection,
                    2,
                    100,
                    &archive_path,
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

    // The repaired store reopens healthy.
    let reopened = SqliteReceiptStore::open(&path)?;
    assert!(reopened.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store whose entire checkpointed history was archived has legitimately empty
/// source tables AND an empty projection. The next writable `open()` must NOT
/// brick it on the empty-projection backfill guard just because a checkpoint or
/// watermark exists; there is nothing to regenerate.
#[test]
fn fully_archived_store_reopens_writable() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("fully-archived-reopen");
    let archive = unique_db_path("fully-archived-reopen-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("fr-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the whole history archives");
    }

    // Reopen writable: the empty expected + empty existing case must be accepted.
    let reopened = SqliteReceiptStore::open(&path)?;
    assert!(reopened.receipt_store_health()?.healthy);
    // And the store is still appendable after the full-prefix rotation.
    let fresh =
        super::support::sample_receipt_with_keypair_and_timestamp("fr-fresh", 9, 900, &keypair);
    reopened.append_chio_receipt_returning_seq(&fresh)?;
    reopened.flush_receipt_writes()?;
    assert!(reopened.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// After a full-prefix rotation the live claim-log table is empty, so the
/// writable checkpoint-status path must floor committed progress at the
/// retention watermark just like the read-only health path. Otherwise it
/// reports committed progress regressing to 0 while the checkpoint chain still
/// sits at the archived boundary W, corrupting health and metrics.
#[test]
fn checkpoint_status_floors_committed_at_watermark_after_full_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("status-floor-watermark");
    let archive = unique_db_path("status-floor-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sf-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    let status = store.receipt_checkpoint_status(None)?;
    assert_eq!(
        status.retention_watermark_entry_seq,
        Some(4),
        "the watermark records the fully archived boundary"
    );
    assert_eq!(
        status.latest_checkpointed_entry_seq, 4,
        "the checkpoint chain still sits at the archived boundary"
    );
    assert_eq!(
        status.latest_committed_entry_seq, 4,
        "committed progress must fold in the archived prefix, not regress to 0"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// `chio receipt flush` reads committed progress from `flush_report`. After a
/// full-prefix rotation deletes every live claim-log row, the live MAX(entry_seq)
/// is 0 while the checkpoint chain and retention watermark still sit at the
/// archived boundary W. Flush committed progress must fold in the archived
/// prefix; a report that regressed to 0 would contradict health/status and
/// corrupt operator flush metrics.
#[test]
fn flush_report_floors_committed_at_watermark_after_full_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("flush-floor-watermark");
    let archive = unique_db_path("flush-floor-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ff-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    let report = store.flush_receipt_writes()?;
    assert_eq!(
        report.latest_checkpointed_entry_seq, 4,
        "the checkpoint chain still sits at the archived boundary"
    );
    assert_eq!(
        report.latest_committed_entry_seq, 4,
        "flush committed progress must fold in the archived prefix, not regress to 0"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The read-only health path must survive a store created before the retention
/// migration: a missing watermark ledger is "never archived" (None), not a hard
/// error that denies the observer every health report.
#[test]
fn read_only_health_ok_on_pre_retention_schema() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("read-only-pre-retention");
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..2u64 {
            let r =
                super::support::sample_receipt_with_keypair(&format!("pr-{i}"), i + 1, &keypair);
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Simulate a pre-retention schema by dropping the watermark ledger the
        // migration would have created. A read-only observer opens without the
        // writable migration, so it must tolerate the missing table.
        store.writer_handle().run_write(|connection| {
            connection.execute_batch("DROP TABLE IF EXISTS receipt_retention_watermark;")?;
            Ok(())
        })?;
        store.flush_receipt_writes()?;
    }

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path)?;
    assert!(
        report.healthy,
        "a pre-retention store must still report health to a read-only observer"
    );
    assert_eq!(report.retention_watermark_entry_seq, None);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A watermark that merely MATCHES a checkpoint boundary is not proof of
/// archival. If the covered rows are still live (a raw INSERT at a real
/// boundary), verification must NOT skip their Merkle rebuild; corruption below
/// the forged boundary must still be caught fail-closed.
#[test]
fn boundary_matching_watermark_over_live_prefix_does_not_skip_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{
        insert_receipt_retention_watermark, verify_checkpoint_chain_integrity,
    };

    let path = unique_db_path("boundary-live-watermark");
    let store = SqliteReceiptStore::open(&path)?;
    let keypair = super::support::receipt_test_keypair();
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two checkpoints cover [1,2] and [3,4]; NOTHING is archived.
    for i in 0..4u64 {
        let receipt =
            super::support::sample_receipt_with_keypair(&format!("bm-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Forge W = 2: a REAL checkpoint boundary (checkpoint 1's batch_end), but the
    // covered rows [1,2] are never deleted. Then tamper a still-live row in that
    // range. A boundary-only exemption would skip the [1,2] rebuild and pass.
    store.writer_handle().run_write(|connection| {
        insert_receipt_retention_watermark(connection, 2, 100, "phantom-archive.sqlite3", None, 1)?;
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 1;",
        )?;
        Ok(())
    })?;

    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "a boundary-matching watermark over a live prefix must not skip verification"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A writer whose verified head is behind a checkpoint another handle archived
/// must still catch up across the boundary. The incremental catch-up path must
/// honor the same archival-watermark exemption as the full chain walk; otherwise
/// it rebuilds the deleted prefix from the live claim log and fails.
#[test]
fn catch_up_honors_archival_watermark_exemption() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("catch-up-watermark");
    let archive = unique_db_path("catch-up-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    // Checkpoints cover [1,2] and [3,4]; the aged [1,2] range is genuinely
    // archived (real archive, watermark W=2, live prefix deleted).
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // A fresh (behind) verified head catching up from seq 0 to seq 2 must process
    // checkpoint 1, whose range [1,2] was archived. Without the exemption the
    // rebuild from the emptied prefix fails; with it (backed by the real archive)
    // the head advances cleanly.
    let connection = store.reader_connection_for_test()?;
    let mut head = crate::receipt_store::VerifiedHead::default();
    crate::receipt_store::catch_up_verified_head_to(&connection, &mut head, 2)?;
    assert_eq!(
        head.checkpoint_seq(),
        2,
        "the head must catch up across the archived boundary"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A full-prefix rotation deletes every live claim-log row, so the read-only
/// watchdog sees a live MAX(entry_seq) of 0 while the latest checkpoint still
/// sits at the archived watermark. Committed progress must fold in the archived
/// prefix so a healthy, fully-archived store is not reported as behind.
#[test]
fn read_only_health_floors_committed_at_watermark() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("read-only-fully-archived");
    let archive = unique_db_path("read-only-fully-archived-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("fa-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Archive the entire checkpointed history: every live claim-log row goes.
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the whole history archives");
        store.flush_receipt_writes()?;
    }

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path)?;
    assert!(
        report.healthy,
        "a fully-archived store must read healthy from the read-only watchdog"
    );
    assert_eq!(report.retention_watermark_entry_seq, Some(4));
    assert_eq!(
        report.latest_committed_entry_seq, 4,
        "committed progress must be floored at the archival watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The watermark-trust reader opens the archive by the path recorded in the
/// ledger, so that path must be absolute: a relative or otherwise non-canonical
/// path resolves against whatever working directory the reader runs in, so a
/// restart or a CLI health check launched elsewhere would find no archive and
/// withdraw the exemption. Give a rotation a non-canonical path (routed through
/// a symlinked directory) and assert the ledger records the resolved location.
#[cfg(unix)]
#[test]
fn rotation_records_absolute_archive_path() -> Result<(), Box<dyn std::error::Error>> {
    let dir = unique_db_path("abs-archive-dir");
    std::fs::create_dir_all(&dir)?;
    let real_archive = dir.join("archive.sqlite3");
    let link = dir.join("dirlink");
    std::os::unix::fs::symlink(&dir, &link)?;
    // Absolute but non-canonical: dir/dirlink/archive.sqlite3 resolves through
    // the symlink to dir/archive.sqlite3.
    let noncanonical = link.join("archive.sqlite3");
    let noncanonical_str = noncanonical.to_str().ok_or("archive path not utf-8")?;

    let path = unique_db_path("abs-archive-store");
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, noncanonical_str, &keypair)?;

    let connection = store.reader_connection_for_test()?;
    let stored: String = connection.query_row(
        "SELECT archive_path FROM receipt_retention_watermark \
         ORDER BY archived_through_entry_seq DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    drop(connection);

    let canonical = std::fs::canonicalize(&real_archive)?;
    let canonical_str = canonical.to_str().ok_or("canonical path not utf-8")?;
    assert_eq!(
        stored, canonical_str,
        "the ledger must record the canonical absolute archive path"
    );
    assert_ne!(
        stored, noncanonical_str,
        "the ledger must not record the non-canonical input path verbatim"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Once the first rotation deletes the archived prefix it can never re-copy
/// those rows, so a later rotation pointed at a DIFFERENT archive would write
/// only the newer suffix there and strand the earlier prefix in the original
/// file, splitting one logical archive across two files that neither alone can
/// satisfy. A rotation whose archive path differs from the one an earlier
/// rotation committed to must be rejected fail-closed before any copy or delete.
#[test]
fn rotation_rejects_archive_path_change_after_first() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("archive-path-change");
    let archive_a = unique_db_path("archive-path-change-a");
    let archive_b = unique_db_path("archive-path-change-b");
    let archive_a_path = archive_a.to_str().ok_or("archive path invalid")?;
    let archive_b_path = archive_b.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two aged batches: [1,2] at timestamp 100, [3,4] at timestamp 200.
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 2..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("b-{i}"),
            i + 1,
            200,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // First rotation archives [1,2] to archive A (W=2).
    let first = store.archive_receipts_before(150, archive_a_path)?;
    assert_eq!(first, 2, "the aged [1,2] batch archives to A");

    // A second rotation would advance to W=4 but names a DIFFERENT archive B: it
    // must be rejected before any copy or delete.
    let result = store.archive_receipts_before(250, archive_b_path);
    let message = result
        .err()
        .ok_or("expected a Conflict; rotation accepted a changed archive path")?
        .to_string();
    assert!(
        message.contains("differs from the archive"),
        "unexpected error: {message}"
    );

    // The [3,4] rows are intact in live: the abort happened before any delete.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no [3,4] rows deleted when the path change is rejected"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive_a);
    let _ = std::fs::remove_file(&archive_b);
    Ok(())
}

/// Primary correctness proof: a state-machine proptest that drives random
/// interleaved sequences of tool/child appends (non-monotonic
/// timestamps within an aged band, to exercise the MAX(timestamp)-over-prefix
/// watermark rule) and rotations against the store, and asserts at every
/// reachable state that the store stays appendable, reopenable, healthy
/// (folding set-equality and chain integrity), and that the archived and live
/// receipt-id sets partition the full appended history with no loss and no
/// double-counting.
// Named `state_machine`, not `prop`: `proptest::prelude::*` re-exports the
// whole proptest crate under the name `prop` (for `prop::collection::vec`
// etc.), so a submodule literally named `prop` combined with `use super::*`
// would glob-import itself and collide with that re-export (E0659 ambiguous
// name).
#[cfg(test)]
mod state_machine {
    use std::collections::BTreeSet;

    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum Op {
        AppendTool(u8),
        AppendChild(u8),
        Rotate,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..8).prop_map(Op::AppendTool),
            (0u8..8).prop_map(Op::AppendChild),
            Just(Op::Rotate),
        ]
    }

    /// Every receipt_id currently in `chio_tool_receipts` union
    /// `chio_child_receipts` on `store` (live or archive database alike).
    fn receipt_id_set(store: &SqliteReceiptStore) -> Result<BTreeSet<String>, ReceiptStoreError> {
        let connection = store.reader_connection_for_test()?;
        let mut ids = BTreeSet::new();
        let mut tool_statement = connection.prepare("SELECT receipt_id FROM chio_tool_receipts")?;
        let tool_rows = tool_statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in tool_rows {
            ids.insert(id?);
        }
        let mut child_statement =
            connection.prepare("SELECT receipt_id FROM chio_child_receipts")?;
        let child_rows = child_statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in child_rows {
            ids.insert(id?);
        }
        Ok(ids)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn prop_retention_preserves_append_invariant(ops in prop::collection::vec(op_strategy(), 1..40)) {
            let path = unique_db_path("prop-retention");
            let archive = unique_db_path("prop-archive");
            let keypair = super::super::support::receipt_test_keypair();
            let archive_path = archive.to_str().ok_or_else(|| TestCaseError::fail("archive path"))?;

            let mut seq = 0u64;
            // The full history of every receipt id ever appended, independent
            // of where it ends up (live or archived): the ground truth that
            // invariant (4) below partitions against.
            let mut appended_ids: BTreeSet<String> = BTreeSet::new();
            {
                let store = SqliteReceiptStore::open(&path).map_err(map_err)?;
                store
                    .enable_background_checkpoints(super::super::support::signer(&keypair, 2))
                    .map_err(map_err)?;
                for (i, op) in ops.iter().enumerate() {
                    // Non-monotonic timestamps within an aged band to exercise
                    // the MAX(timestamp)-over-prefix watermark rule.
                    let ts = 100 + ((i as u64 * 7) % 13);
                    match op {
                        Op::AppendTool(n) => {
                            seq += 1;
                            let r = super::super::support::sample_receipt_with_keypair_and_timestamp(
                                &format!("pt-{seq}-{n}"), seq, ts, &keypair);
                            appended_ids.insert(r.id.clone());
                            store.append_chio_receipt_returning_seq(&r).map_err(map_err)?;
                        }
                        Op::AppendChild(n) => {
                            seq += 1;
                            let r = super::super::support::sample_child_receipt_with_keypair_seq_and_timestamp(
                                &format!("pc-{seq}-{n}"), seq, ts, &keypair);
                            appended_ids.insert(r.id.clone());
                            store.append_child_receipt_record(&r).map_err(map_err)?;
                        }
                        Op::Rotate => {
                            store.flush_receipt_writes().map_err(map_err)?;
                            // Cutoff above BOTH the aged op band (100..=112) and
                            // the probe band (2_000), so every timestamp is
                            // below the cutoff and any fully checkpointed prefix
                            // is eligible for archival. The archival watermark
                            // W = MAX(batch_end_seq) is a PREFIX rule: a
                            // checkpoint qualifies only if no entry in [1, W]
                            // has timestamp >= cutoff. A cutoff below the probe
                            // band would let the low-seq probes poison every
                            // prefix and make the co-archive-and-delete path a
                            // permanent no-op (W = 0), so the archived/live
                            // partition below would never actually be exercised.
                            store.archive_receipts_before(3_000, archive_path).map_err(map_err)?;
                        }
                    }
                    // Invariant (1): the next append still succeeds.
                    seq += 1;
                    let probe = super::super::support::sample_receipt_with_keypair_and_timestamp(
                        &format!("probe-{seq}"), seq, 2_000, &keypair);
                    appended_ids.insert(probe.id.clone());
                    store.append_chio_receipt_returning_seq(&probe).map_err(map_err)?;
                    // Invariant (3): health stays healthy (folds set-equality
                    // and chain integrity).
                    store.flush_receipt_writes().map_err(map_err)?;
                    prop_assert!(store.receipt_store_health().map_err(map_err)?.healthy);
                }
            }
            // Invariant (2): reopen succeeds (open-time seed re-verifies).
            let reopened = SqliteReceiptStore::open(&path).map_err(map_err)?;
            prop_assert!(reopened.receipt_store_health().map_err(map_err)?.healthy);

            // Invariant (4): the archived and live receipt-id sets partition
            // the full appended history. No id is lost (union covers
            // everything ever appended) and none is double-counted (the two
            // sets are disjoint). A run with no eligible rotation leaves the
            // archive set empty and everything live, which still satisfies
            // the partition.
            let live_ids = receipt_id_set(&reopened).map_err(map_err)?;
            let archive_store = SqliteReceiptStore::open(&archive).map_err(map_err)?;
            let archived_ids = receipt_id_set(&archive_store).map_err(map_err)?;
            let overlap: Vec<&String> = live_ids.intersection(&archived_ids).collect();
            prop_assert!(
                overlap.is_empty(),
                "receipt ids double-counted in both live and archive: {overlap:?}"
            );
            let union: BTreeSet<String> = live_ids.union(&archived_ids).cloned().collect();
            prop_assert_eq!(
                union,
                appended_ids,
                "archived and live receipt-id sets must partition the full appended history"
            );

            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&archive);
        }
    }

    fn map_err(error: ReceiptStoreError) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }
}
