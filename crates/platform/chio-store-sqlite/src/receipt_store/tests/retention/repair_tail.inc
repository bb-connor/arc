/// Retention repair rounds its cleanup boundary up to a checkpoint boundary.
/// When the orphaned rows cover only PART of that batch, rows above them may
/// still have live source receipts. Even an existing committed watermark at the
/// boundary cannot authorize partial-batch cleanup. Repair must refuse it
/// fail-closed.
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
        provision_test_archive_file(&archive)?;
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
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                commit_attached_repair_archive_authority(connection, &archive_path, 4)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END;",
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
        .ok_or("expected a partial-batch refusal; repair deleted an incomplete batch")?
        .to_string();
    assert!(
        message.contains("partially archived batch"),
        "unexpected error: {message}"
    );

    // Fail-closed: the precommitted watermark is unchanged and the orphans
    // survive.
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
    let watermark: Option<i64> = live.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(
        watermark,
        Some(4),
        "repair must leave the precommitted watermark unchanged"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair consumes a precommitted checkpoint-aligned watermark that
/// trusts the whole `[1, rounded]` prefix as archived. Verifying only surviving
/// orphaned rows is not enough: a botched rotation may also have deleted some
/// projection rows in that prefix outright. Repair must verify a faithful
/// archive row for every entry before cleanup and refuse otherwise.
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
        provision_test_archive_file(&archive)?;
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
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 4)?;
                connection.execute_batch(
                    "DELETE FROM archive.chio_tool_receipts WHERE seq IN (1, 2); \
                     DELETE FROM archive.claim_receipt_log_entries WHERE entry_seq IN (1, 2);",
                )?;
                commit_attached_repair_archive_authority(connection, &archive_path, 4)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 4; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
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

    // Fail-closed: the precommitted watermark is unchanged and the surviving
    // orphans remain.
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
        watermark,
        Some(4),
        "repair must neither replace nor advance the precommitted watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A botched rotation can commit a watermark and then fail before removing the
/// orphaned claim-log rows it left behind. Repair may clean those remnants only
/// under that existing authority and must leave the ledger byte-for-byte
/// unchanged.
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
        provision_test_archive_file(&archive)?;
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
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                commit_attached_repair_archive_authority(connection, &archive_path, 2)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
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

#[test]
fn repair_rejects_unexpected_tombstone_trigger_before_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-malicious-tombstone-trigger");
    let archive = unique_db_path("repair-malicious-tombstone-trigger-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    prepare_committed_repair_archive_fixture(
        &store,
        &archive,
        archive_path,
        &keypair,
        "repair-malicious-tombstone-trigger",
        2,
        2,
        2,
    )?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 2;",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        connection.execute_batch(
            "CREATE TRIGGER repair_malicious_tombstone_claim_delete \
             AFTER INSERT ON receipt_retention_tombstones \
             BEGIN \
                 DELETE FROM claim_receipt_log_entries \
                 WHERE receipt_id = NEW.receipt_id; \
             END;",
        )?;
        Ok(())
    })?;
    drop(store);

    let store = SqliteReceiptStore::open_existing(&path)?;
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair executed an unexpected tombstone trigger")?;
    assert!(
        error
            .to_string()
            .contains("trigger catalog contains a missing or unexpected trigger"),
        "unexpected malicious-trigger refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 2, "trigger refusal must preserve every orphan");
    assert_eq!(tombstones, 0, "trigger refusal must precede tombstone writes");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_temp_trigger_before_any_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-temp-trigger");
    let archive = unique_db_path("repair-temp-trigger-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    prepare_committed_repair_archive_fixture(
        &store,
        &archive,
        archive_path,
        &keypair,
        "repair-temp-trigger",
        2,
        2,
        2,
    )?;
    let refusal = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        move |connection| {
            connection.execute_batch(
                "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                 DELETE FROM chio_tool_receipts WHERE seq <= 2;",
            )?;
            crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
            connection.execute_batch(
                "CREATE TEMP TRIGGER poison_repair_tombstone_insert \
                 AFTER INSERT ON main.receipt_retention_tombstones \
                 BEGIN \
                     DELETE FROM claim_receipt_log_entries \
                     WHERE receipt_id = NEW.receipt_id; \
                 END",
            )?;
            let error = crate::receipt_store::evidence_retention::retention_repair_on_writer(
                connection,
                &archive_path,
            )
            .err()
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "retention repair accepted an active TEMP trigger".to_string(),
                )
            })?;
            connection.execute_batch("DROP TRIGGER temp.poison_repair_tombstone_insert")?;
            Ok(error.to_string())
        }
    })?;
    assert!(
        refusal.contains("TEMP trigger"),
        "unexpected TEMP-trigger refusal: {refusal}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let freezes: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_capability_freezes",
        [],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 2, "TEMP refusal must preserve every orphan");
    assert_eq!(freezes, 0, "TEMP refusal must precede freeze backfill");
    assert_eq!(tombstones, 0, "TEMP refusal must precede tombstones");
    drop(live);
    drop(store);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_uses_committed_watermark_beyond_candidate_checkpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-committed-superset");
    let archive = unique_db_path("repair-committed-superset-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let receipt_ids = prepare_committed_repair_archive_fixture(
        &store,
        &archive,
        archive_path,
        &keypair,
        "repair-committed-superset",
        4,
        2,
        4,
    )?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 4; \
             DELETE FROM claim_receipt_log_entries WHERE entry_seq > 2 AND entry_seq <= 4;",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;
    drop(store);

    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 2, "only the two selected orphan claims are deleted");
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones \
         WHERE archived_through_entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    let freezes: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_capability_freezes",
        [],
        |row| row.get(0),
    )?;
    let misbound_freezes: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_capability_freezes \
         WHERE archived_through_entry_seq != 4 OR frozen_at != 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 0);
    assert_eq!(
        tombstones, 4,
        "repair must tombstone the complete committed prefix, not only the rounded candidates"
    );
    assert!(freezes > 0, "repair must backfill capability freeze authority");
    assert_eq!(
        misbound_freezes, 0,
        "repair freezes must bind to the committed watermark metadata"
    );
    drop(live);
    let archive_read = rusqlite::Connection::open(&archive)?;
    let archived_capabilities: i64 = archive_read.query_row(
        "SELECT COUNT(DISTINCT receipt.capability_id) \
         FROM chio_tool_receipts receipt \
         INNER JOIN claim_receipt_log_entries claim \
             ON claim.source_seq = receipt.seq \
            AND claim.receipt_id = receipt.receipt_id \
            AND claim.receipt_kind = 'tool_receipt' \
         WHERE claim.entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        freezes, archived_capabilities,
        "repair freeze ledger must exactly cover the archive capability set"
    );
    drop(archive_read);
    let archived = store
        .load_chio_receipt(&receipt_ids[2])?
        .ok_or("committed-prefix point lookup missed a receipt above the candidate checkpoint")?;
    assert_eq!(archived.id, receipt_ids[2]);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_live_overlap_above_candidate_checkpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-live-overlap");
    let archive = unique_db_path("repair-live-overlap-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    prepare_committed_repair_archive_fixture(
        &store,
        &archive,
        archive_path,
        &keypair,
        "repair-live-overlap",
        4,
        2,
        4,
    )?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 2;",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;
    drop(store);

    let store = SqliteReceiptStore::open_existing(&path)?;
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair accepted live receipt overlap inside the committed prefix")?;
    assert!(
        error
            .to_string()
            .contains("overlaps a distinct live claim occurrence"),
        "unexpected overlap refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 4, "overlap refusal must preserve all live claims");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_forged_capability_freeze_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-forged-capability-freeze");
    let archive = unique_db_path("repair-forged-capability-freeze-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    prepare_committed_repair_archive_fixture(
        &store,
        &archive,
        archive_path,
        &keypair,
        "repair-forged-capability-freeze",
        2,
        2,
        2,
    )?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 2; \
             INSERT INTO receipt_retention_capability_freezes \
                 (capability_id, archived_through_entry_seq, frozen_at) \
             VALUES ('forged-unarchived-capability', 2, 1);",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;

    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair accepted capability freeze authority absent from the archive")?;
    assert!(
        error
            .to_string()
            .contains("freeze ledger contains authority absent from the archive"),
        "unexpected forged-freeze refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 2, "freeze refusal must preserve repair candidates");
    assert_eq!(tombstones, 0, "freeze refusal must precede tombstone writes");
    drop(live);
    drop(store);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_late_lineage_before_freeze_backfill(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-late-lineage-freeze");
    let archive = unique_db_path("repair-late-lineage-freeze-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..4_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("repair-late-lineage-freeze-{index}"),
            index + 1,
            100,
            &keypair,
        );
        let receipt = if index < 2 {
            receipt
        } else {
            let mut body = receipt.body();
            body.capability_id = "cap-late".to_string();
            chio_core::receipt::body::ChioReceipt::sign(body, &keypair)?
        };
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    provision_test_archive_file(&archive)?;
    store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
            copy_complete_repair_archive_prefix(connection, 4)?;
            commit_attached_repair_archive_authority(connection, &archive_path, 4)?;
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(())
        }
    })?;
    store.writer_handle().run_write(|connection| {
        connection.execute(
            "INSERT INTO capability_lineage \
             (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, \
              delegation_depth, parent_capability_id) \
             VALUES ('cap-late', 'late-subject', 'late-issuer', 1, 200, '[]', 0, NULL)",
            [],
        )?;
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 4; \
             DELETE FROM claim_receipt_log_entries WHERE entry_seq > 2 AND entry_seq <= 4;",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;

    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair backfilled freezes over late live lineage")?;
    assert!(
        error
            .to_string()
            .contains("live capability lineage for archived capability \"cap-late\" is absent or divergent"),
        "unexpected late-lineage refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let freezes: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_capability_freezes",
        [],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 2, "lineage refusal preserves repair candidates");
    assert_eq!(freezes, 0, "lineage refusal must precede freeze backfill");
    assert_eq!(tombstones, 0, "lineage refusal must precede tombstones");
    drop(live);
    drop(store);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_unrelated_suffix_projection_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    for corruption in ["source-only", "divergent"] {
        let path = unique_db_path(&format!("repair-suffix-{corruption}"));
        let archive = unique_db_path(&format!("repair-suffix-{corruption}-archive"));
        let archive_path = archive.to_str().ok_or("archive path invalid")?;
        let keypair = super::support::receipt_test_keypair();
        let store = SqliteReceiptStore::open(&path)?;
        prepare_committed_repair_archive_fixture(
            &store,
            &archive,
            archive_path,
            &keypair,
            &format!("repair-suffix-{corruption}"),
            4,
            2,
            2,
        )?;
        store.writer_handle().run_write({
            let corruption = corruption.to_string();
            move |connection| {
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM chio_tool_receipts WHERE seq <= 2;",
                )?;
                match corruption.as_str() {
                    "source-only" => connection.execute_batch(
                        "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                         DELETE FROM claim_receipt_log_entries WHERE entry_seq = 3;",
                    )?,
                    "divergent" => connection.execute_batch(
                        "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
                         UPDATE claim_receipt_log_entries SET raw_json = '{}' \
                         WHERE entry_seq = 3;",
                    )?,
                    _ => return Err(ReceiptStoreError::Conflict("unknown fixture".to_string())),
                }
                crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
                Ok(())
            }
        })?;
        drop(store);

        let store = SqliteReceiptStore::open_existing(&path)?;
        let error = store
            .retention_repair(archive_path)
            .err()
            .ok_or("repair ignored unrelated suffix projection drift")?;
        let message = error.to_string();
        assert!(
            message.contains("missing for live tool_receipt source row")
                || message.contains("diverges from its live tool_receipt source row"),
            "unexpected {corruption} refusal: {message}"
        );
        let live = store.reader_connection_for_test()?;
        let orphans: i64 = live.query_row(
            "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(orphans, 2, "suffix refusal must preserve repair candidates");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
    }
    Ok(())
}

#[test]
fn repair_refuses_unfinished_settlement_barriers(
) -> Result<(), Box<dyn std::error::Error>> {
    for (barrier, expected_message) in [
        (
            "observer-outbox",
            "unfinished settlement observer delivery entered the archival prefix",
        ),
        (
            "settle-attempt",
            "settlement retry entered the archival prefix",
        ),
    ] {
        let path = unique_db_path(&format!("repair-{barrier}"));
        let archive = unique_db_path(&format!("repair-{barrier}-archive"));
        let archive_path = archive.to_str().ok_or("archive path invalid")?;
        let keypair = super::support::receipt_test_keypair();
        let store = SqliteReceiptStore::open(&path)?;
        let receipt_ids = prepare_committed_repair_archive_fixture(
            &store,
            &archive,
            archive_path,
            &keypair,
            &format!("repair-{barrier}"),
            2,
            2,
            2,
        )?;
        if barrier == "settle-attempt" {
            drop(crate::SqliteSettlementRetryStore::open_alongside(
                &store,
            )?);
        }
        store.writer_handle().run_write({
            let barrier = barrier.to_string();
            let receipt_id = receipt_ids[0].clone();
            move |connection| {
                match barrier.as_str() {
                    "observer-outbox" => {
                        connection.execute(
                            "INSERT INTO chio_settlement_observer_outbox \
                             (receipt_id, finalized_at) VALUES (?1, 100)",
                            rusqlite::params![receipt_id],
                        )?;
                    }
                    "settle-attempt" => {
                        connection.execute(
                            "INSERT INTO settle_attempts \
                             (receipt_id, finalized_at, attempts, next_visible_at, \
                              last_reason, updated_at) \
                             VALUES (?1, 100, 1, 200, 'retryable', 100)",
                            rusqlite::params![receipt_id],
                        )?;
                    }
                    _ => {
                        return Err(ReceiptStoreError::Conflict(
                            "unknown settlement barrier fixture".to_string(),
                        ));
                    }
                }
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM chio_tool_receipts WHERE seq <= 2;",
                )?;
                crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
                Ok(())
            }
        })?;

        let error = store
            .retention_repair(archive_path)
            .err()
            .ok_or("repair ignored unfinished settlement evidence")?;
        assert!(
            error.to_string().contains(expected_message),
            "unexpected {barrier} refusal: {error}"
        );
        let live = store.reader_connection_for_test()?;
        let claims: i64 = live.query_row(
            "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
            [],
            |row| row.get(0),
        )?;
        let tombstones: i64 = live.query_row(
            "SELECT COUNT(*) FROM receipt_retention_tombstones",
            [],
            |row| row.get(0),
        )?;
        let barrier_rows: i64 = match barrier {
            "observer-outbox" => live.query_row(
                "SELECT COUNT(*) FROM chio_settlement_observer_outbox",
                [],
                |row| row.get(0),
            )?,
            "settle-attempt" => {
                live.query_row("SELECT COUNT(*) FROM settle_attempts", [], |row| row.get(0))?
            }
            _ => 0,
        };
        assert_eq!(claims, 2, "barrier refusal must preserve every orphan");
        assert_eq!(barrier_rows, 1, "barrier refusal preserves its evidence");
        assert_eq!(tombstones, 0, "barrier refusal must precede mutation");
        drop(live);
        drop(store);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
    }
    Ok(())
}

#[test]
fn repair_refuses_terminal_iou_residue_without_orphaning_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-terminal-iou");
    let archive = unique_db_path("repair-terminal-iou-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    let mut receipt_ids = Vec::new();
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("repair-terminal-iou-{index}"),
            index + 1,
            100,
            &keypair,
        );
        receipt_ids.push(receipt.id.clone());
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    drop(SqliteIouEnvelopeStore::open_alongside(&store)?);
    store.writer_handle().run_write({
        let receipt_id = receipt_ids[0].clone();
        move |connection| {
            connection.execute(
                "INSERT INTO iou_envelope \
                 (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, \
                  issuer_key, canonical_json) \
                 VALUES (?1, 'repair-terminal-iou', 100, NULL, 1, 'USD', 'issuer', '{}')",
                rusqlite::params![receipt_id],
            )?;
            connection.execute(
                "INSERT INTO settlement_reconciliations \
                 (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'reconciled', 'terminal', 100)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    provision_test_archive_file(&archive)?;
    store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
            copy_complete_repair_archive_prefix(connection, 2)?;
            commit_attached_repair_archive_authority(connection, &archive_path, 2)?;
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(())
        }
    })?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "PRAGMA foreign_keys = OFF; \
             DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 2;",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        connection.execute_batch("PRAGMA foreign_keys = ON")?;
        let foreign_keys: i64 =
            connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        if foreign_keys != 1 {
            return Err(ReceiptStoreError::Conflict(
                "terminal IOU fixture failed to restore foreign keys".to_string(),
            ));
        }
        Ok(())
    })?;

    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair orphaned a terminal IOU")?;
    assert!(
        error
            .to_string()
            .contains("IOU envelope exists without its exact authoritative live receipt"),
        "unexpected terminal IOU refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let ious: i64 = live.query_row(
        "SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = ?1",
        rusqlite::params![receipt_ids[0]],
        |row| row.get(0),
    )?;
    let reconciliations: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_ids[0]],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 2, "terminal IOU refusal preserves orphan claims");
    assert_eq!(ious, 1, "repair must not delete the terminal IOU");
    assert_eq!(
        reconciliations, 1,
        "repair must not delete the terminal settlement record"
    );
    assert_eq!(tombstones, 0, "terminal IOU refusal precedes mutation");
    drop(live);
    drop(store);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rechecks_suffix_checkpoint_projections_before_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-suffix-checkpoint-projection");
    let archive = unique_db_path("repair-suffix-checkpoint-projection-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    prepare_committed_repair_archive_fixture(
        &store,
        &archive,
        archive_path,
        &keypair,
        "repair-suffix-checkpoint-projection",
        6,
        2,
        2,
    )?;
    assert!(
        store.load_checkpoint_by_seq(3)?.is_some(),
        "checkpoint 2 must be an interior suffix checkpoint in this fixture"
    );
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DELETE FROM chio_tool_receipts WHERE seq <= 2; \
             DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update; \
             UPDATE checkpoint_tree_heads SET merkle_root = 'tampered' \
             WHERE checkpoint_seq = 2;",
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;

    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair committed despite suffix checkpoint projection drift")?;
    assert!(
        error
            .to_string()
            .contains("checkpoint tree head projection for checkpoint 2 diverges"),
        "unexpected checkpoint-projection refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let claims: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let tombstones: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(claims, 2, "precommit refusal rolls back orphan deletion");
    assert_eq!(tombstones, 0, "precommit refusal rolls back tombstones");
    drop(live);
    drop(store);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
