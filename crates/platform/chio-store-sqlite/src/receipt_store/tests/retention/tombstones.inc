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

/// The watermark exemption skips the live Merkle rebuild for the archived prefix
/// and trusts the archive to serve that deep verification. A count of archived
/// rows is not enough: an archive holding the right number of rows but with
/// tampered contents no longer hashes to the signed checkpoint roots. Trust must
/// be withdrawn when the archived receipts no longer re-derive the signed roots,
/// even though the archived row count is unchanged.
#[test]
fn watermark_trust_rejects_tampered_archive_contents() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::trusted_retention_watermark;

    let path = unique_db_path("watermark-tampered");
    let archive = unique_db_path("watermark-tampered-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // A faithful archive backs the watermark.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(trusted_retention_watermark(&connection)?, 2);
    drop(connection);

    // Tamper the archived claim-log contents WITHOUT changing the row count: the
    // archive still holds two entries for [1,2], but one no longer matches the
    // receipt that was checkpointed.
    {
        let tampered = rusqlite::Connection::open(&archive)?;
        let changed = tampered.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' \
             WHERE entry_seq = 1",
            [],
        )?;
        assert_eq!(changed, 1, "exactly one archived row tampered");
    }

    // The row count is still 2, but the archived prefix no longer re-derives the
    // signed checkpoint root, so the exemption is withdrawn fail-closed.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "a watermark whose archive no longer matches the signed roots must not be trusted"
    );

    drop(connection);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair deletes the surviving orphaned claim-log rows for receipts
/// whose source rows are already gone. Those orphan rows hold the last live
/// UNIQUE(receipt_id) sentinel, so repair must tombstone each archived id before
/// deleting it, exactly as the rotation delete does. Otherwise the same archived
/// receipt_id could be appended again as a brand-new live receipt, recreating
/// the archived/live identity ambiguity the tombstone exists to prevent.
#[test]
fn repair_tombstones_archived_ids_to_block_reuse() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-tombstone");
    let archive = unique_db_path("repair-tombstone-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a bricked store: co-archive the claim-log for [1,2], then delete
    // ONLY the source receipt rows (leaving the claim-log rows -> set drift).
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("dup-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
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

    // Repair the bricked store.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 2, "repair removed the two orphaned claim-log rows");
    drop(store);

    // The repaired (archived) ids are tombstoned, so re-appending one as a fresh
    // live receipt is rejected: the archived id cannot be resurrected.
    let reopened = SqliteReceiptStore::open(&path)?;
    let reused =
        super::support::sample_receipt_with_keypair_and_timestamp("dup-0", 1, 100, &keypair);
    let result = reopened.append_chio_receipt_returning_seq(&reused);
    assert!(
        result.is_err(),
        "re-appending an archived receipt id must be rejected by the retention tombstone"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair must tombstone EVERY archived id in the repaired prefix, not only the
/// claim-log rows that survived as extras. When a botched rotation already
/// deleted some archived rows from the live projection, those ids have no live
/// UNIQUE(receipt_id) sentinel AND no extra to iterate, so tombstoning only the
/// extras would leave them re-appendable and recreate the archived/live identity
/// ambiguity. Re-appending an already-deleted archived id must still be rejected.
#[test]
fn repair_tombstones_already_deleted_prefix_ids() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-tombstone-prefix");
    let archive = unique_db_path("repair-tombstone-prefix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a store, co-archive [1,2], then fabricate a mixed drift: delete the
    // source rows for [1,2] AND the LIVE claim-log row for entry_seq 1, leaving
    // only entry_seq 2 as a surviving orphan. Entry 1's archived id is gone from
    // the live projection entirely, so it is not an extra repair would iterate.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("pre-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
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
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 1; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // Repair removes only the surviving orphan (entry 2) but must tombstone the
    // whole archived prefix [1,2].
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 1, "repair removed the one surviving orphaned row");
    drop(store);

    // The already-deleted archived id (entry 1, "pre-0") must be tombstoned too:
    // re-appending it as a fresh live receipt is rejected.
    let reopened = SqliteReceiptStore::open(&path)?;
    let reused =
        super::support::sample_receipt_with_keypair_and_timestamp("pre-0", 1, 100, &keypair);
    let result = reopened.append_chio_receipt_returning_seq(&reused);
    assert!(
        result.is_err(),
        "re-appending an already-deleted archived receipt id must be rejected by the tombstone"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rolls_back_when_an_existing_tombstone_conflicts_with_the_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-conflicting-tombstone");
    let archive = unique_db_path("repair-conflicting-tombstone-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let first_receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "repair-conflicting-tombstone-0",
        1,
        100,
        &keypair,
    );
    let first_receipt_id = first_receipt.id.clone();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        store.append_chio_receipt_returning_seq(&first_receipt)?;
        let second_receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            "repair-conflicting-tombstone-1",
            2,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&second_receipt)?;
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;

        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            let first_receipt_id = first_receipt_id.clone();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                commit_attached_repair_archive_authority(connection, &archive_path, 2)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END;",
                )?;
                connection.execute(
                    "INSERT INTO receipt_retention_tombstones \
                         (receipt_id, receipt_kind, archived_through_entry_seq, tombstoned_at) \
                     VALUES (?1, 'child_receipt', 2, 100)",
                    rusqlite::params![first_receipt_id],
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair accepted a tombstone whose receipt kind conflicts with the archive")?;
    assert!(
        error
            .to_string()
            .contains("conflicts with the trusted archive prefix"),
        "unexpected conflicting tombstone refusal: {error}"
    );

    let live = store.reader_connection_for_test()?;
    let surviving_orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        surviving_orphans, 2,
        "a conflicting tombstone must roll back every candidate deletion"
    );
    let watermark_rows: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_watermark",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        watermark_rows, 1,
        "repair must preserve the one precommitted authority row"
    );
    let retained_conflict: (i64, String) = live.query_row(
        "SELECT COUNT(*), MIN(receipt_kind) FROM receipt_retention_tombstones",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(retained_conflict, (1, "child_receipt".to_string()));

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_uses_one_recorded_archive_snapshot_after_a_path_replacement(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::retention_repair_on_writer_with_precommit_boundary_for_test;

    let path = unique_db_path("repair-one-archive-snapshot");
    let archive = unique_db_path("repair-one-archive-snapshot-recorded");
    let replacement = unique_db_path("repair-one-archive-snapshot-replacement");
    let displaced = unique_db_path("repair-one-archive-snapshot-displaced");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let replacement_path = replacement.to_str().ok_or("replacement path invalid")?;
    let displaced_path = displaced.to_str().ok_or("displaced path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let first_receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "repair-one-archive-snapshot-0",
        1,
        100,
        &keypair,
    );
    let first_receipt_id = first_receipt.id.clone();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        store.append_chio_receipt_returning_seq(&first_receipt)?;
        let second_receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            "repair-one-archive-snapshot-1",
            2,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&second_receipt)?;
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
        provision_test_archive_file(&replacement)?;

        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            let replacement_path = replacement_path.to_string();
            move |connection| {
                let escaped_archive = archive_path.replace('\'', "''");
                let escaped_replacement = replacement_path.replace('\'', "''");
                let shared_nonce = uuid::Uuid::now_v7().to_string();
                connection.execute_batch(&format!(
                    "ATTACH DATABASE '{escaped_archive}' AS archive;"
                ))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                let archive_identity =
                    install_test_archive_identity(connection, "archive", &shared_nonce)?;
                let archive_content_sha256 =
                    crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                        connection,
                        "archive",
                        2,
                    )?;
                record_repair_archive_authority(
                    connection,
                    &archive_path,
                    2,
                    &archive_identity,
                    &archive_content_sha256,
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                connection.execute_batch(&format!(
                    "ATTACH DATABASE '{escaped_replacement}' AS archive;"
                ))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                install_test_archive_identity(connection, "archive", &shared_nonce)?;
                connection.execute_batch("DETACH DATABASE archive")?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 1; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
                )?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let archive_path = archive_path.to_string();
    let replacement_path = replacement_path.to_string();
    let displaced_path = displaced_path.to_string();
    let boundary_archive_path = archive_path.clone();
    let mut recovery_connection = rusqlite::Connection::open(&path)?;
    let result = retention_repair_on_writer_with_precommit_boundary_for_test(
        &mut recovery_connection,
        &archive_path,
        move || {
            std::fs::rename(&boundary_archive_path, &displaced_path)?;
            std::fs::rename(&replacement_path, &boundary_archive_path)?;
            Ok(())
        },
    );
    drop(recovery_connection);
    let message = result
        .err()
        .ok_or("repair accepted a same-content archive path replacement")?
        .to_string();
    assert!(
        message.contains("ownership changed before the live commit"),
        "unexpected path replacement refusal: {message}"
    );

    let live = store.reader_connection_for_test()?;
    let faithful_tombstone: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_retention_tombstones WHERE receipt_id = ?1",
        rusqlite::params![first_receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(faithful_tombstone, 0);
    let surviving_orphan: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq = 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(surviving_orphan, 1, "rejected repair preserves the orphan");

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&replacement);
    let _ = std::fs::remove_file(&displaced);
    Ok(())
}

/// Repair stamps tombstones from the SUPPLIED archive, but the archive that
/// actually backs an already-committed watermark is the LEDGER's archive. When a
/// caller supplies a different archive that happens to be faithful for the
/// surviving orphans yet divergent for prefix entries already deleted from the
/// live projection, the root re-derivation still passed against the ledger
/// archive while the tombstones were stamped for the wrong receipt ids, leaving
/// the truly archived ids re-appendable. Repair must require the supplied archive
/// to be the ledger archive so both run against the one archive that backs the
/// watermark; a mismatch fails closed.
#[test]
fn repair_rejects_archive_that_does_not_back_the_watermark(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-wrong-backing");
    let ledger_archive = unique_db_path("repair-wrong-backing-ledger");
    let ledger_path = ledger_archive
        .to_str()
        .ok_or("ledger archive path invalid")?;
    let supplied_archive = unique_db_path("repair-wrong-backing-supplied");
    let supplied_path = supplied_archive
        .to_str()
        .ok_or("supplied archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Mixed drift: co-archive [1,2] into the LEDGER archive, delete the source
    // rows for [1,2] and the LIVE claim-log row for entry 1 (fully deleted,
    // tombstoned only from the archive), leaving entry 2 as the surviving orphan.
    // Record a watermark at boundary 2 naming the ledger archive.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("wb-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&ledger_archive)?;
        provision_test_archive_file(&supplied_archive)?;
        store.writer_handle().run_write({
            let ledger_path = ledger_path.to_string();
            let supplied_path = supplied_path.to_string();
            move |connection| {
                let ledger_escaped = ledger_path.replace('\'', "''");
                // The ledger archive faithfully backs [1,2] so its checkpoint root
                // re-derives.
                connection
                    .execute_batch(&format!("ATTACH DATABASE '{ledger_escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2;",
                )?;
                let shared_nonce = uuid::Uuid::now_v7().to_string();
                let archive_identity =
                    install_test_archive_identity(connection, "archive", &shared_nonce)?;
                let archive_content_sha256 =
                    crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                        connection,
                        "archive",
                        2,
                    )?;
                connection.execute_batch("DETACH DATABASE archive")?;

                // The SUPPLIED archive is faithful for the surviving orphan (entry
                // 2) but carries a divergent row for the already-deleted entry 1.
                let supplied_escaped = supplied_path.replace('\'', "''");
                connection
                    .execute_batch(&format!("ATTACH DATABASE '{supplied_escaped}' AS supplied"))?;
                crate::receipt_store::evidence_retention::create_archive_schema_in_schema_for_test(
                    connection,
                    "supplied",
                )?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS supplied.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO supplied.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq = 2; \
                     INSERT INTO supplied.claim_receipt_log_entries \
                       (entry_seq, receipt_id, receipt_kind, source_seq, timestamp, raw_json) \
                       VALUES (1, 'wrong-archived-id', 'tool_receipt', 1, 100, '{\"wrong\":true}');",
                )?;
                install_test_archive_identity(connection, "supplied", &shared_nonce)?;
                connection.execute_batch("DETACH DATABASE supplied")?;

                // Fabricate the drift.
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 1; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
                )?;
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection,
                    2,
                    100,
                    &ledger_path,
                    &archive_identity,
                    &archive_content_sha256,
                    1,
                )?;
                Ok(())
            }
        })?;
    }

    // Repair with the divergent archive must fail closed instead of tombstoning
    // from an archive that does not back the committed watermark.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(supplied_path);
    let message = result
        .err()
        .ok_or("expected repair to reject an archive that does not back the watermark")?
        .to_string();
    assert!(
        message.contains("differs from the archive"),
        "unexpected error: {message}"
    );

    // Fail-closed: the surviving orphan is untouched, so a correct re-run against
    // the ledger archive can still complete.
    let live = store.reader_connection_for_test()?;
    let orphan_present: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq = 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphan_present, 1,
        "a rejected repair must leave the orphan for a correct re-run"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&ledger_archive);
    let _ = std::fs::remove_file(&supplied_archive);
    Ok(())
}

/// In incremental mode the rotation skips the O(N) chain rebuild on the append
/// hot path and trusts the per-append verified head, which can lag
/// `kernel_checkpoints` when a second store instance appends checkpoint rows
/// this handle has not adopted. The rotation path itself still audits the FULL
/// persisted checkpoint chain before pruning, so it must cap the archival
/// watermark at the freshest VERIFIED boundary (the latest persisted checkpoint)
/// rather than the possibly-stale in-memory head. Otherwise a quiet store that
/// another instance advanced would archive nothing every interval despite
/// holding aged, checkpointed receipts.
#[test]
fn rotation_archives_to_freshest_verified_checkpoint_despite_stale_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotation-verified-ceiling");
    let archive = unique_db_path("rotation-verified-ceiling-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Instance A checkpoints [1,2] and keeps its verified head at boundary 2.
    let store_a = SqliteReceiptStore::open(&path)?;
    store_a.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ceil-a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store_a.append_chio_receipt_returning_seq(&r)?;
    }
    store_a.flush_receipt_writes()?;
    assert!(store_a.load_checkpoint_by_seq(1)?.is_some());

    // A second instance appends [3,4] and builds checkpoint 2 covering boundary
    // 4. Instance A stays idle, so its cached verified head never advances past
    // boundary 2 even though the DB now holds an aged, checkpointed [1,4].
    {
        let store_b = SqliteReceiptStore::open_existing(&path)?;
        store_b.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 2..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("ceil-b-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store_b.append_chio_receipt_returning_seq(&r)?;
        }
        store_b.flush_receipt_writes()?;
        assert!(store_b.load_checkpoint_by_seq(2)?.is_some());
    }

    // Rotate through the stale instance A. Its cached head sits at boundary 2,
    // but the rotation audits the full persisted chain and archives the whole
    // aged, verified [1,4] instead of stalling at the stale head.
    let archived = store_a.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 4,
        "rotation must archive to the freshest verified checkpoint boundary"
    );

    let conn = store_a.reader_connection_for_test()?;
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        watermark,
        Some(4),
        "the watermark advances to the freshest verified boundary"
    );
    let survivors: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        survivors, 0,
        "the aged, verified checkpoint's rows are pruned once the chain is audited"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A legacy database can reach a repair-capable existing open without retention
/// metadata. That open must restore and validate the watermark ledger before its
/// actor starts, so a following rotation can record its archival boundary.
#[test]
fn existing_open_restores_missing_watermark_ledger_before_rotation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("legacy-rotation-watermark");
    let archive = unique_db_path("legacy-rotation-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("lgr-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(2)?.is_some());
        // Drop the watermark ledger so the store looks like it predates the
        // retention migration.
        store.writer_handle().run_write(|connection| {
            connection.execute_batch("DROP TABLE IF EXISTS receipt_retention_watermark;")?;
            Ok(())
        })?;
    }

    // Reopen through the repair-capable existing path, which restores retention
    // metadata before actor startup, then rotate.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 4,
        "the aged checkpointed prefix archives once the ledger is created"
    );

    let conn = store.reader_connection_for_test()?;
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        watermark,
        Some(4),
        "the rotation created the ledger and recorded the boundary"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Once a rotation deletes the live receipt (and its `UNIQUE(receipt_id)`
/// sentinel), the tombstone row is the only DB-level record that the id was
/// archived, so it must be as immutable as the append-only projection tables. A
/// writer that bypasses the Rust path must not be able to delete or rewrite a
/// tombstone and then re-insert the archived id.
#[test]
fn retention_tombstones_are_immutable() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("tombstone-immutable");
    let store = SqliteReceiptStore::open(&path)?;
    let conn = store.reader_connection_for_test()?;

    // open() creates the tombstone table; seed one row (INSERT stays allowed).
    conn.execute(
        "INSERT INTO receipt_retention_tombstones \
         (receipt_id, receipt_kind, archived_through_entry_seq, tombstoned_at) \
         VALUES ('archived-1', 'tool_receipt', 5, 100)",
        [],
    )?;

    // A raw UPDATE is rejected by the reject-update trigger.
    let updated = conn.execute(
        "UPDATE receipt_retention_tombstones SET archived_through_entry_seq = 999",
        [],
    );
    assert!(
        updated.is_err(),
        "raw UPDATE of a tombstone must be rejected"
    );

    // A raw DELETE is rejected by the reject-delete trigger.
    let deleted = conn.execute("DELETE FROM receipt_retention_tombstones", []);
    assert!(
        deleted.is_err(),
        "raw DELETE of a tombstone must be rejected"
    );

    // The tombstone is unchanged: still exactly the one seeded row.
    let (count, seq): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(MAX(archived_through_entry_seq), 0) FROM receipt_retention_tombstones",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(count, 1);
    assert_eq!(seq, 5);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn rotation_rolls_back_when_an_existing_tombstone_conflicts_with_the_live_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotation-conflicting-tombstone");
    let archive = unique_db_path("rotation-conflicting-tombstone-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    let first = super::support::sample_receipt_with_keypair_and_timestamp(
        "rotation-conflicting-tombstone-0",
        1,
        100,
        &keypair,
    );
    let first_id = first.id.clone();
    store.append_chio_receipt_returning_seq(&first)?;
    let second = super::support::sample_receipt_with_keypair_and_timestamp(
        "rotation-conflicting-tombstone-1",
        2,
        100,
        &keypair,
    );
    store.append_chio_receipt_returning_seq(&second)?;
    store.flush_receipt_writes()?;
    store.writer_handle().run_write(move |connection| {
        connection.execute(
            "INSERT INTO receipt_retention_tombstones \
                 (receipt_id, receipt_kind, archived_through_entry_seq, tombstoned_at) \
             VALUES (?1, 'child_receipt', 2, 1)",
            rusqlite::params![first_id],
        )?;
        Ok(())
    })?;

    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or("rotation accepted a tombstone that conflicts with its live receipt")?;
    assert!(
        error
            .to_string()
            .contains("conflicts with the exact archive suffix"),
        "unexpected conflicting rotation tombstone refusal: {error}"
    );
    assert_eq!(store.tool_receipt_count()?, 2);
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_log, 2);
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        None
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn current_version_existing_opens_reject_a_weakened_retention_watermark_trigger(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("weakened-watermark-trigger");
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.writer_handle().run_write(|connection| {
            connection.execute_batch(
                "DROP TRIGGER receipt_retention_watermark_reject_regression; \
                 CREATE TRIGGER receipt_retention_watermark_reject_regression \
                 BEFORE INSERT ON receipt_retention_watermark \
                 BEGIN SELECT 1; END;",
            )?;
            Ok(())
        })?;
    }

    let error = SqliteReceiptStore::open_existing(&path)
        .err()
        .ok_or("repair-capable existing open accepted a weakened watermark trigger")?;
    assert!(
        error
            .to_string()
            .contains("receipt_retention_watermark_reject_regression is invalid"),
        "unexpected weakened watermark refusal: {error}"
    );
    let strict_error = SqliteReceiptStore::open_existing_strict(&path)
        .err()
        .ok_or("strict existing open accepted a weakened watermark trigger")?;
    assert!(
        strict_error
            .to_string()
            .contains("receipt_retention_watermark_reject_regression is invalid"),
        "unexpected strict weakened watermark refusal: {strict_error}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn current_version_existing_opens_reject_a_watermark_table_without_its_check(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("watermark-table-without-check");
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.writer_handle().run_write(|connection| {
            connection.execute_batch(
                "DROP TABLE receipt_retention_watermark; \
                 CREATE TABLE receipt_retention_watermark ( \
                     archived_through_entry_seq INTEGER NOT NULL, \
                     archived_through_timestamp INTEGER NOT NULL, \
                     archive_path TEXT NOT NULL, \
                     archive_sha256 TEXT, \
                     rotated_at INTEGER NOT NULL \
                 );",
            )?;
            Ok(())
        })?;
    }

    let error = SqliteReceiptStore::open_existing(&path)
        .err()
        .ok_or("repair-capable existing open accepted a watermark table without its check")?;
    assert!(
        error
            .to_string()
            .contains("receipt_retention_watermark does not match the required schema"),
        "unexpected malformed watermark table refusal: {error}"
    );
    let strict_error = SqliteReceiptStore::open_existing_strict(&path)
        .err()
        .ok_or("strict existing open accepted a watermark table without its check")?;
    assert!(
        strict_error
            .to_string()
            .contains("receipt_retention_watermark does not match the required schema"),
        "unexpected strict malformed watermark table refusal: {strict_error}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn current_version_existing_opens_reject_replace_on_conflict_tombstone_primary_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("replace-tombstone-primary-key");
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.writer_handle().run_write(|connection| {
            connection.execute_batch(
                "DROP TABLE receipt_retention_tombstones; \
                 CREATE TABLE receipt_retention_tombstones ( \
                     receipt_id TEXT PRIMARY KEY ON CONFLICT REPLACE, \
                     receipt_kind TEXT NOT NULL, \
                     archived_through_entry_seq INTEGER NOT NULL, \
                     tombstoned_at INTEGER NOT NULL \
                 );",
            )?;
            Ok(())
        })?;
    }

    let error = SqliteReceiptStore::open_existing(&path)
        .err()
        .ok_or("repair-capable existing open accepted a replace tombstone primary key")?;
    assert!(
        error
            .to_string()
            .contains("receipt_retention_tombstones does not match the required schema"),
        "unexpected malformed tombstone refusal: {error}"
    );
    let strict_error = SqliteReceiptStore::open_existing_strict(&path)
        .err()
        .ok_or("strict existing open accepted a replace tombstone primary key")?;
    assert!(
        strict_error
            .to_string()
            .contains("receipt_retention_tombstones does not match the required schema"),
        "unexpected strict malformed tombstone refusal: {strict_error}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}
