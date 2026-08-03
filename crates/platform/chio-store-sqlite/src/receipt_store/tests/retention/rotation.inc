#[test]
fn repeated_rotations_verify_and_archive_only_each_new_suffix(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::retention_watermark;

    let path = unique_db_path("repeated-rotation-suffix");
    let archive = unique_db_path("repeated-rotation-suffix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;

    for index in 0..6_u64 {
        let timestamp = 100 + (index / 2) * 100;
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("repeated-rotation-suffix-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    assert_eq!(store.archive_receipts_before(150, archive_path)?, 2);
    assert_eq!(store.archive_receipts_before(250, archive_path)?, 2);
    assert_eq!(store.archive_receipts_before(350, archive_path)?, 2);

    let live = store.reader_connection_for_test()?;
    assert_eq!(retention_watermark(&live)?, Some(6));
    let live_rows: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_rows, 0);
    let identity_ledger: (i64, i64, i64, i64, i64) = live.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT archive_sha256), \
                SUM(CASE WHEN archive_sha256 IS NULL THEN 1 ELSE 0 END), \
                COUNT(DISTINCT archive_content_sha256), \
                SUM(CASE WHEN archive_content_sha256 IS NULL THEN 1 ELSE 0 END) \
         FROM receipt_retention_watermark",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!(
        identity_ledger,
        (3, 1, 0, 3, 0),
        "every rotation retains one identity and a mandatory content snapshot"
    );
    let ledger_identity: String = live.query_row(
        "SELECT archive_sha256 FROM receipt_retention_watermark \
         ORDER BY archived_through_entry_seq DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;

    let archived = rusqlite::Connection::open(&archive)?;
    let archived_rows: i64 = archived.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(archived_rows, 6);
    let archive_identity: String = archived.query_row(
        "SELECT commitment_sha256 FROM chio_retention_archive_identity \
         WHERE identity_slot = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(archive_identity, ledger_identity);

    drop(archived);
    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn rotation_migrates_a_committed_legacy_archive_catalog(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        legacy_retention_archive_prefix_content_sha256,
        retention_archive_prefix_content_sha256,
    };
    use crate::receipt_store::support::{
        ensure_receipt_retention_watermark_table, retention_watermark,
    };

    let path = unique_db_path("legacy-archive-catalog");
    let archive = unique_db_path("legacy-archive-catalog-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;

    for index in 0..4_u64 {
        let timestamp = 100 + (index / 2) * 100;
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("legacy-archive-catalog-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(
        store
            .archive_receipts_before(150, archive_path)
            .unwrap_or_else(|error| panic!("legacy fixture initial rotation failed: {error}")),
        2
    );

    let legacy_digest = {
        let archive_connection = rusqlite::Connection::open(&archive)?;
        archive_connection.execute(
            "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = ?2",
            rusqlite::params![
                crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION + 1,
                crate::receipt_store::RECEIPT_STORE_SCHEMA_KEY
            ],
        )?;
        let invalid_version =
            legacy_retention_archive_prefix_content_sha256(&archive_connection, "main", 2)
                .expect_err("legacy compatibility must reject an untrusted version row");
        assert!(invalid_version
            .to_string()
            .contains("current singleton receipt schema-version row"));
        archive_connection.execute(
            "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = ?2",
            rusqlite::params![
                crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
                crate::receipt_store::RECEIPT_STORE_SCHEMA_KEY
            ],
        )?;
        archive_connection.execute_batch("DROP TABLE chio_store_schema_versions")?;
        legacy_retention_archive_prefix_content_sha256(&archive_connection, "main", 2)
            .unwrap_or_else(|error| panic!("legacy archive digest failed: {error}"))
    };
    store.writer_handle().run_write({
        let legacy_digest = legacy_digest.clone();
        move |connection| {
            connection.execute_batch(
                "DROP TRIGGER receipt_retention_watermark_reject_update",
            )?;
            connection.execute(
                "UPDATE receipt_retention_watermark SET archive_content_sha256 = ?1 \
                 WHERE archived_through_entry_seq = 2",
                rusqlite::params![legacy_digest],
            )?;
            ensure_receipt_retention_watermark_table(connection)?;
            Ok(())
        }
    })?;

    assert_eq!(
        store
            .archive_receipts_before(250, archive_path)
            .unwrap_or_else(|error| panic!("legacy archive migration failed: {error}")),
        2
    );

    let live = store.reader_connection_for_test()?;
    assert_eq!(retention_watermark(&live)?, Some(4));
    let committed_digest: String = live.query_row(
        "SELECT archive_content_sha256 FROM receipt_retention_watermark \
         ORDER BY archived_through_entry_seq DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let archived = rusqlite::Connection::open(&archive)?;
    let schema_version: i32 = archived.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
        [crate::receipt_store::RECEIPT_STORE_SCHEMA_KEY],
        |row| row.get(0),
    )?;
    assert_eq!(
        schema_version,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    assert_eq!(
        retention_archive_prefix_content_sha256(&archived, "main", 4)?,
        committed_digest
    );

    drop(archived);
    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Settlement and metered reconciliation rows are mutated in place by ongoing
/// reconciliation upserts, so a rotation can copy a reconciliation row, have a
/// later update change it, and then abort under the write-locked co-archival
/// re-verify because the archive holds the pre-update bytes. The archive copy of
/// these mutable tables must REFRESH a conflicting stale row from the current
/// live row; an `INSERT OR IGNORE` retry would keep the stale bytes and leave
/// the prefix permanently unrotatable.
#[test]
fn rotation_refreshes_stale_reconciliation_archive_rows() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("recon-refresh");
    let archive = unique_db_path("recon-refresh-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("recon-refresh-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // The current (already reconciled) live rows for the first archived receipt.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'reconciled', 'live-note', 200)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-final', 42, 42, 'usd', NULL, 200, 'reconciled', 'live-note', 200)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    // Simulate the archive an earlier rotation left behind: a copy of the
    // reconciliation rows captured BEFORE the update above, so the archived
    // bytes are now stale. The bulk evidence tables are created and copied
    // faithfully by the rotation itself.
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            r#"
            CREATE TABLE settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY, reconciliation_state TEXT NOT NULL,
                note TEXT, updated_at INTEGER NOT NULL
            );
            CREATE TABLE metered_billing_reconciliations (
                receipt_id TEXT PRIMARY KEY, adapter_kind TEXT NOT NULL,
                evidence_id TEXT NOT NULL, observed_units INTEGER NOT NULL,
                billed_cost_units INTEGER NOT NULL, billed_cost_currency TEXT NOT NULL,
                evidence_sha256 TEXT, recorded_at INTEGER NOT NULL,
                reconciliation_state TEXT NOT NULL, note TEXT, updated_at INTEGER NOT NULL
            );
            "#,
        )?;
        seed.execute(
            "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
             VALUES (?1, 'ignored', 'stale-note', 100)",
            rusqlite::params![receipt_id],
        )?;
        seed.execute(
            "INSERT INTO metered_billing_reconciliations \
             (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
             VALUES (?1, 'test', 'ev-stale', 1, 1, 'usd', NULL, 100, 'ignored', 'stale-note', 100)",
            rusqlite::params![receipt_id],
        )?;
    }
    restrict_test_archive_file(&archive)?;

    // Rotation must refresh the stale archive rows and complete, not stall on
    // the pre-update bytes.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "rotation must refresh the stale archived reconciliation rows and complete"
    );

    // The archive now holds the current live reconciliation state.
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let settled_state: String = arch.query_row(
        "SELECT reconciliation_state FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        settled_state, "reconciled",
        "the archived settlement row must refresh to the current live state"
    );
    let metered_units: i64 = arch.query_row(
        "SELECT observed_units FROM metered_billing_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        metered_units, 42,
        "the archived metered row must refresh to the current live units"
    );

    // The live rows are gone (co-archived, not cascaded).
    let live = store.reader_connection_for_test()?;
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_settlement, 0, "settlement row absent from live");

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
    assert!(
        store.writer_serving_closed(),
        "pre-rotation integrity verification must publish the fail-closed health bit before returning"
    );
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ran_in_job = std::sync::Arc::clone(&ran);
    let subsequent: Result<(), ReceiptStoreError> =
        store.writer_handle().run_write(move |_connection| {
            ran_in_job.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
    assert!(
        subsequent.is_err(),
        "the local head poisoned by rotation verification must reject a later write"
    );
    assert!(
        !ran.load(std::sync::atomic::Ordering::SeqCst),
        "the poisoned writer must not execute a later write closure"
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
    provision_test_archive_file(&archive)?;

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
                   BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END;",
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
    assert!(
        store.writer_serving_closed(),
        "pre-rotation projection corruption must publish the fail-closed health bit"
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

/// An incremental store's per-append verified head attests only NEW appends, so
/// it never notices a retroactive deletion of BOTH a checkpoint-covered source
/// row and its claim-log projection row. That drift leaves the source and
/// projection sets matching (the projection audit passes) while the covering
/// checkpoint's claim-log range falls short of its signed tree_size. Rotation
/// must audit the live checkpoint chain before deleting even in incremental
/// mode and fail closed, rather than co-archive only the survivors, delete the
/// rest, and stamp a watermark the archive can never back (a bricked store with
/// its remaining live evidence gone).
#[test]
fn incremental_rotation_audits_chain_before_deleting() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("incremental-chain-audit-rotation");
    let archive = unique_db_path("incremental-chain-audit-rotation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // A default open() store runs incremental verification, so the per-append
    // head is trusted and the O(N) chain rebuild would otherwise be skipped.
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
    // Checkpoint [1,2] covers entry_seq 1 and 2 with a signed tree_size of 2.
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Retroactively delete BOTH the source row and its claim-log row for a
    // checkpoint-[1,2]-covered receipt. The source and projection sets both lose
    // the same receipt, so they stay in agreement and the projection audit
    // passes; only the checkpoint chain audit notices the now-short covered range.
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM main.chio_tool_receipts WHERE seq = 2; \
             DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 2; \
             CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
               BEFORE DELETE ON chio_tool_receipts \
               BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
             CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
               BEFORE DELETE ON claim_receipt_log_entries \
               BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
        )?;
        Ok(())
    })?;

    // The rotation must detect the short checkpoint range and fail closed BEFORE
    // any archive-and-delete.
    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or(
            "rotation over an unaudited checkpoint chain must fail closed, not archive-and-delete",
        )?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the chain audit, got {error:?}"
    );
    assert!(
        store.writer_serving_closed(),
        "pre-rotation checkpoint corruption must publish the fail-closed health bit"
    );

    // Fail-closed: the surviving live evidence for [1,2] was not deleted.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 1,
        "the surviving covered claim-log row must not be deleted when the chain is unaudited"
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
    assert!(
        !store.writer_serving_closed(),
        "an invalid archive target is a configuration refusal, not evidence corruption"
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
    assert!(
        !store.writer_serving_closed(),
        "a self-aliasing archive target must be refused without poisoning a healthy receipt log"
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
/// command and the actor's Rotate arm must release it after the outcome is
/// final. Without that release `receipt_store_health().writer.inflight` would
/// report a permanently in-flight writer after any rotation.
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

/// A dequeued rotation continues to own the single writer while SQLite waits
/// for a conflicting writer lock. The health counter and liveness verdict must
/// describe that running work until the lock is released and rotation answers.
#[test]
fn blocked_rotation_remains_inflight_and_reports_wedged() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("blocked-rotate-inflight");
    let archive = unique_db_path("blocked-rotate-inflight-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("blocked-inflight-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let blocker = rusqlite::Connection::open(&path)?;
    blocker.execute_batch("PRAGMA busy_timeout = 0; BEGIN IMMEDIATE")?;
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let rotation = scope.spawn(|| store.archive_receipts_before(150, archive_path));

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let health = store.receipt_store_health()?;
            if health.writer.inflight == 1 && health.writer.queue_depth == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "rotation was not observed running: inflight={}, queue_depth={}",
                    health.writer.inflight, health.writer.queue_depth
                )
                .into());
            }
            std::thread::yield_now();
        }
        assert_eq!(
            store.writer_liveness(Duration::ZERO),
            chio_kernel::ReceiptWriterLiveness::Wedged,
            "a dequeued rotation blocked on SQLite must trip writer liveness"
        );

        blocker.execute_batch("ROLLBACK")?;
        let archived = rotation.join().map_err(|_| "rotation thread panicked")??;
        assert_eq!(archived, 4, "rotation resumes after the lock is released");
        Ok(())
    })?;

    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "completed rotation releases its in-flight writer slot"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
