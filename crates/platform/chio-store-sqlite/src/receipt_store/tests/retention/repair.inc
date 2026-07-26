fn copy_complete_repair_archive_prefix(
    connection: &rusqlite::Connection,
    watermark: i64,
) -> Result<(), ReceiptStoreError> {
    crate::receipt_store::evidence_retention::copy_archived_prefix(connection, watermark)?;
    Ok(())
}

fn record_repair_archive_authority(
    connection: &rusqlite::Connection,
    archive_path: &str,
    watermark: u64,
    archive_identity: &str,
    archive_content_sha256: &str,
) -> Result<(), ReceiptStoreError> {
    crate::receipt_store::support::insert_receipt_retention_watermark(
        connection,
        watermark,
        100,
        archive_path,
        archive_identity,
        archive_content_sha256,
        1,
    )
}

fn commit_attached_repair_archive_authority(
    connection: &rusqlite::Connection,
    archive_path: &str,
    watermark: i64,
) -> Result<(), ReceiptStoreError> {
    let journal_mode: String = connection.query_row(
        "PRAGMA archive.journal_mode = DELETE",
        [],
        |row| row.get(0),
    )?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(ReceiptStoreError::Conflict(format!(
            "test repair archive remained in {journal_mode:?} journal mode"
        )));
    }
    let archive_identity = install_fresh_test_archive_identity(connection)?;
    let archive_content_sha256 =
        crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
            connection,
            "archive",
            watermark,
        )?;
    record_repair_archive_authority(
        connection,
        archive_path,
        crate::receipt_store::support::sqlite_positive_u64(
            watermark,
            "test repair authority watermark",
        )?,
        &archive_identity,
        &archive_content_sha256,
    )
}

fn prepare_committed_repair_archive_fixture(
    store: &SqliteReceiptStore,
    archive: &std::path::Path,
    archive_path: &str,
    keypair: &super::support::Keypair,
    receipt_prefix: &str,
    receipt_count: u64,
    checkpoint_batch: u64,
    archive_watermark: i64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    store.enable_background_checkpoints(super::support::signer(
        keypair,
        checkpoint_batch,
    ))?;
    let mut receipt_ids = Vec::new();
    for index in 0..receipt_count {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("{receipt_prefix}-{index}"),
            index + 1,
            100,
            keypair,
        );
        receipt_ids.push(receipt.id.clone());
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    provision_test_archive_file(archive)?;
    store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
            copy_complete_repair_archive_prefix(connection, archive_watermark)?;
            commit_attached_repair_archive_authority(
                connection,
                &archive_path,
                archive_watermark,
            )?;
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(())
        }
    })?;
    Ok(receipt_ids)
}

/// Retention repair owns its in-flight lease through both the repair transaction
/// and verified-head reseed. A conflicting SQLite writer lock makes that
/// lifetime observable deterministically: after the command leaves the queue it
/// cannot answer until the lock is released, so health must continue reporting
/// one in-flight writer and then return exactly to zero.
#[test]
fn blocked_retention_repair_remains_inflight_until_completion(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("blocked-repair-inflight");
    let archive = unique_db_path("blocked-repair-inflight-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build the repairable set-drift shape: a complete checkpointed claim-log
    // prefix survives in both live and archive while its live source receipts
    // have been deleted.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for index in 0..2_u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("blocked-repair-inflight-{index}"),
                index + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped_archive = archive_path.replace('\'', "''");
                connection
                    .execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
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
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "repair starts from a drained writer"
    );
    let blocker = rusqlite::Connection::open(&path)?;
    blocker.execute_batch("PRAGMA busy_timeout = 0; BEGIN IMMEDIATE")?;
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let repair = scope.spawn(|| store.retention_repair(archive_path));

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let inflight = store
                .receipt_commit_actor
                .health
                .inflight
                .load(std::sync::atomic::Ordering::SeqCst);
            let queue_depth = store
                .receipt_commit_actor
                .health
                .queue_depth
                .load(std::sync::atomic::Ordering::SeqCst);
            if inflight == 1 && queue_depth == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "retention repair was not observed running: inflight={}, queue_depth={}",
                    inflight, queue_depth
                )
                .into());
            }
            std::thread::yield_now();
        }
        assert!(
            !repair.is_finished(),
            "the conflicting BEGIN IMMEDIATE must keep retention repair blocked"
        );
        assert_eq!(
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a dequeued retention repair must retain its in-flight lease while blocked"
        );
        assert_eq!(
            store.writer_liveness(Duration::ZERO),
            chio_kernel::ReceiptWriterLiveness::Wedged,
            "a retention repair blocked on SQLite must trip writer liveness"
        );

        blocker.execute_batch("ROLLBACK")?;
        let removed = repair
            .join()
            .map_err(|_| "retention repair thread panicked")??;
        assert_eq!(removed, 2, "repair resumes after the lock is released");
        Ok(())
    })?;

    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "completed retention repair releases its in-flight writer slot"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_claim_log_only_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-claim-only");
    let archive = unique_db_path("repair-claim-only-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for index in 0..2_u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("repair-claim-only-{index}"),
                index + 1,
                100,
                &keypair,
            );
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
                connection.execute_batch(
                    "INSERT INTO archive.claim_receipt_log_entries \
                         SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     INSERT INTO archive.kernel_checkpoints \
                         SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= 2;",
                )?;
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
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair trusted an archive with claims but no source receipts")?;
    assert!(
        error.to_string().contains("chio_tool_receipts"),
        "missing source refusal did not identify the source table: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(orphans, 2, "a rejected repair preserves every orphan");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_source_projection_divergence() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-source-divergence");
    let archive = unique_db_path("repair-source-divergence-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for index in 0..2_u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("repair-source-divergence-{index}"),
                index + 1,
                100,
                &keypair,
            );
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
                copy_complete_repair_archive_prefix(connection, 2)?;
                connection.execute_batch(
                    "UPDATE archive.chio_tool_receipts \
                         SET raw_json = (SELECT raw_json FROM archive.chio_tool_receipts WHERE seq = 2) \
                         WHERE seq = 1;",
                )?;
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
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair trusted a source row divergent from its claim projection")?;
    assert!(
        error.to_string().contains("chio_tool_receipts"),
        "divergent source refusal did not identify the source table: {error}"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn repair_rejects_missing_archived_auxiliary_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-missing-auxiliary");
    let archive = unique_db_path("repair-missing-auxiliary-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for index in 0..2_u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("repair-missing-auxiliary-{index}"),
                index + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        store.writer_handle().run_write(|connection| {
            connection.execute(
                "INSERT INTO capability_lineage \
                     (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, \
                      delegation_depth, parent_capability_id) \
                 VALUES ('cap-1', 'repair-subject', 'repair-issuer', 1, 200, '[]', 0, NULL)",
                [],
            )?;
            Ok(())
        })?;
        provision_test_archive_file(&archive)?;
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                connection.execute_batch(
                    "DELETE FROM archive.capability_lineage WHERE capability_id = 'cap-1';",
                )?;
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
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair trusted an archive missing retained capability lineage")?;
    assert!(
        error.to_string().contains("capability_lineage"),
        "missing auxiliary refusal did not identify the evidence table: {error}"
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
        insert_receipt_retention_watermark(
            connection,
            100,
            100,
            "bogus-archive.sqlite3",
            TEST_ARCHIVE_IDENTITY_SHA256,
            TEST_ARCHIVE_CONTENT_SHA256,
            1,
        )?;
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
    restrict_test_archive_file(&archive)?;

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
    assert!(
        store.writer_serving_closed(),
        "a divergent archive discovered during rotation must publish the fail-closed health bit"
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
                delegation_depth INTEGER NOT NULL DEFAULT 0, parent_capability_id TEXT,
                federated_parent_capability_id TEXT,
                provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                    CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection')),
                signed_capability_json TEXT
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
    restrict_test_archive_file(&archive)?;

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
    let mut archived_receipt_ids = Vec::new();

    // Build a bricked store: archive and delete the source rows for a
    // checkpointed range but leave the claim-log rows behind.
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
            archived_receipt_ids.push(r.id.clone());
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
        // Fabricate the bricked state after copying the complete retained
        // evidence surface for [1,2].
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
    let archived_receipt_id = archived_receipt_ids
        .first()
        .ok_or("bricked repair fixture produced no archived receipt ids")?;
    let archived = repaired
        .load_chio_receipt(archived_receipt_id)?
        .ok_or("trusted point lookup missed the repaired archived receipt")?;
    assert_eq!(&archived.id, archived_receipt_id);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair may clean remnants only under authority committed by an earlier
/// rotation. A complete archive without a committed watermark is evidence, not
/// authority, and cannot authorize deletion of the surviving claim rows.
#[test]
fn repair_refuses_complete_archive_without_committed_watermark(
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
        provision_test_archive_file(&archive)?;
        // Preserve a complete archive but deliberately provide no committed
        // watermark authority before deleting the live source rows.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
                     DROP TABLE IF EXISTS receipt_retention_watermark;",
                )?;
                install_fresh_test_archive_identity(connection)?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair created authority for an uncommitted archive")?;
    assert!(
        error.to_string().contains("existing committed archival watermark"),
        "unexpected no-authority refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(orphans, 2, "authority refusal preserves every orphan");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair cannot extend archival authority. A watermark committed through
/// entry 2 may authorize cleanup in `[1, 2]`, but it cannot authorize orphaned
/// rows in the later checkpoint ending at entry 4.
#[test]
fn repair_refuses_when_committed_watermark_does_not_cover_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-watermark-does-not-cover");
    let archive = unique_db_path("repair-watermark-does-not-cover-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for index in 0..4_u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("repair-watermark-does-not-cover-{index}"),
                index + 1,
                100,
                &keypair,
            );
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
                copy_complete_repair_archive_prefix(connection, 2)?;
                commit_attached_repair_archive_authority(connection, &archive_path, 2)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 4; \
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
    let error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("repair extended authority past its committed watermark")?;
    assert!(
        error
            .to_string()
            .contains("exceeds the committed archival watermark 2"),
        "unexpected non-covering authority refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(orphans, 4, "authority refusal preserves every orphan");
    let watermark: Option<i64> = live.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(watermark, Some(2), "repair must not advance the watermark");

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
        crate::receipt_store::evidence_retention::create_archive_schema_in_schema_for_test(
            &seed, "main",
        )?;
        seed.execute(
            "INSERT INTO chio_tool_receipts \
             (seq, receipt_id, timestamp, capability_id, tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES (9001, ?1, 100, 'cap', 'srv', 'tool', 'allow', 'ph', 'ch', ?2)",
            rusqlite::params![receipt_id, raw_json],
        )?;
    }
    restrict_test_archive_file(&archive)?;

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
        crate::receipt_store::evidence_retention::create_archive_schema_in_schema_for_test(
            &seed, "main",
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
    restrict_test_archive_file(&archive)?;

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
        provision_test_archive_file(&archive)?;
        // Fabricate the bricked state, but co-archive a DIVERGENT projection: same
        // receipt_id and entry_seq, wrong source_seq. Then delete the source rows
        // for [1,2], leaving orphaned claim-log rows.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 2)?;
                connection.execute_batch(
                    "UPDATE archive.claim_receipt_log_entries \
                         SET source_seq = source_seq + 500 WHERE entry_seq <= 2;",
                )?;
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

include!("repair_tail.inc");
