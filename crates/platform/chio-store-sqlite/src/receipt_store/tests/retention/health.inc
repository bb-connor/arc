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

/// Direct trait callers read committed progress from `latest_committed_entry_seq`.
/// After a full-prefix rotation empties the live claim-log table, its raw
/// MAX(entry_seq) is 0 while the checkpoint chain and retention watermark still
/// sit at the archived boundary W. This accessor must fold in the archived
/// prefix like the status/health/flush paths, otherwise a `ReceiptStore` caller
/// sees committed regress to 0 until the next append.
#[test]
fn latest_committed_entry_seq_floors_at_watermark_after_full_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("committed-floor-watermark");
    let archive = unique_db_path("committed-floor-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lc-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    assert_eq!(
        store.latest_committed_entry_seq()?,
        4,
        "committed progress must fold in the archived prefix, not regress to 0"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// After a full-prefix rotation, removing the backing archive withdraws the
/// watermark's trust, so the checkpoint chain fails to verify: status reports a
/// checkpoint_error while the committed floor still sits at the archived
/// boundary W. `receipt_store_health` must surface that prepared unhealthy
/// report, not re-probe the [1, W] range whose rows retention already deleted -
/// a probe that would turn the report into a hard error and hide the
/// checkpoint_error operators need.
#[test]
fn health_reports_checkpoint_error_without_probing_archived_rows(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("health-missing-archive");
    let archive = unique_db_path("health-missing-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("hm-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    // Remove the archive backing the deleted [1,4] prefix. The watermark is no
    // longer trusted, so chain verification fails and the committed floor (W = 4)
    // now looks like a backlog over rows retention deleted.
    std::fs::remove_file(&archive)?;

    let report = store.receipt_store_health()?;
    assert!(!report.healthy, "a missing backing archive is unhealthy");
    assert!(
        report.checkpoint_error.is_some(),
        "the checkpoint_error must be surfaced, not swallowed by a hard error from probing deleted rows"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// An authorization receipt in an aged checkpointed prefix whose consumer
/// receipt is still live must not be archived-and-deleted: doing so would strand
/// the live consumer's `chio_authorization_receipt_consumptions` binding. The
/// watermark must stop below the authorization so the whole pair archives
/// together on a later rotation, and the live binding survives in the meantime.
#[test]
fn rotation_preserves_binding_for_live_consumer_of_aged_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("live-consumer-binding");
    let archive = unique_db_path("live-consumer-binding-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Checkpoints [1,2] and [3,4] are fully aged; [5,6] is fresh. The
    // authorization sits at entry 3 (aged) and its consumer at entry 5 (fresh),
    // so a naive cutoff would archive the authorization while the consumer stays
    // live and split their binding.
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lb-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lb-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let authorization_id = receipt_id_at(3)?;
    let consumer_id = receipt_id_at(5)?;
    store.writer_handle().run_write({
        let authorization_id = authorization_id.clone();
        let consumer_id = consumer_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO chio_authorization_receipt_consumptions \
                 (authorization_receipt_id, consumer_receipt_id, request_id, session_id, tool_call_id, tenant_id, parameter_hash, consumed_at_unix_ms) \
                 VALUES (?1, ?2, 'req-lb', 'sess-lb', 'call-lb', NULL, 'hash-lb', 1000)",
                rusqlite::params![authorization_id, consumer_id],
            )?;
            Ok(())
        }
    })?;

    // The watermark must stop at 2 (below the aged authorization at entry 3), not
    // advance to 4 and strand the live consumer's binding.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below the authorization whose consumer is still live"
    );

    let live = store.reader_connection_for_test()?;
    let surviving: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        surviving, 1,
        "the live consumer's authorization-consumption binding must survive the rotation"
    );
    let binding: (String, String) = live.query_row(
        "SELECT authorization_receipt_id, consumer_receipt_id \
         FROM chio_authorization_receipt_consumptions",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    assert_eq!(
        binding,
        (authorization_id.clone(), consumer_id),
        "the surviving binding must still bind the live consumer to its authorization"
    );
    let authorization_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE receipt_id = ?1",
        rusqlite::params![authorization_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        authorization_live, 1,
        "the authorization backing the live binding must remain live"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A surviving child receipt records its parent in
/// `receipt_lineage_statements.parent_receipt_id`, and lineage verification
/// resolves that parent only in the live receipt tables. Rotation must not
/// advance the watermark past a lineage parent whose child is still live, or the
/// child would lose its verified parent and governed call-chain validation would
/// fail for a session whose parent just aged out.
#[test]
fn rotation_preserves_live_child_lineage_parent() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("lineage-parent-preserve");
    let archive = unique_db_path("lineage-parent-preserve-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Checkpoints [1,2] and [3,4] are fully aged; [5,6] is fresh. The lineage
    // parent sits at entry 3 (aged) and its child at entry 5 (fresh), so a naive
    // cutoff would archive the parent while the child stays live and strand the
    // child's verified lineage.
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lp-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lp-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let parent_id = receipt_id_at(3)?;
    let child_id = receipt_id_at(5)?;
    // The live child (entry 5) records the aged receipt (entry 3) as its lineage
    // parent.
    store.writer_handle().run_write({
        let parent_id = parent_id.clone();
        let child_id = child_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO receipt_lineage_statements \
                 (receipt_id, statement_id, request_id, session_id, session_anchor_id, chain_id, \
                  parent_request_id, parent_receipt_id, evidence_class, evidence_sources_json, \
                  verified_session_anchor, verified_parent_request, verified_parent_receipt, \
                  replay_protected, recorded_at, source_kind, json_sha256, raw_json) \
                 VALUES (?1, 'stmt-lp', NULL, NULL, NULL, 'chain-lp', NULL, ?2, 'delegated', NULL, \
                         0, 0, 1, 0, 500, 'test', 'sha-lp', '{\"schema\":\"lineage\"}')",
                rusqlite::params![child_id, parent_id],
            )?;
            Ok(())
        }
    })?;

    // The watermark must stop at 2 (below the aged parent at entry 3), not
    // advance to 4 and delete the parent the live child still points at.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below the lineage parent whose child is still live"
    );

    let live = store.reader_connection_for_test()?;
    let parent_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE receipt_id = ?1",
        rusqlite::params![parent_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        parent_live, 1,
        "the lineage parent backing the live child must remain live"
    );
    let parent_receipt_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![parent_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        parent_receipt_live, 1,
        "the parent's source receipt must survive so lineage verification can resolve it"
    );
    let lineage_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1 AND parent_receipt_id = ?2",
        rusqlite::params![child_id, parent_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        lineage_live, 1,
        "the live child's lineage row must still bind it to the surviving parent"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A receipt whose settlement reconciliation is still `open` hosts the only live
/// row the reconciliation upsert and operator reports can act on, and the upsert
/// requires that receipt to still exist in `chio_tool_receipts`. Rotation must
/// not advance the watermark past an aged receipt with a nonterminal
/// reconciliation, or the actionable item vanishes and the next reconciliation
/// attempt fails NotFound. Once the reconciliation reaches a terminal state a
/// later rotation archives the receipt and its reconciliation together.
#[test]
fn rotation_preserves_receipt_with_open_settlement_reconciliation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("open-settlement-preserve");
    let archive = unique_db_path("open-settlement-preserve-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Checkpoints [1,2] and [3,4] are fully aged; [5,6] is fresh. The receipt at
    // entry 3 (aged) carries an open settlement reconciliation, so a naive cutoff
    // would archive it and strand its only live, actionable reconciliation row.
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("os-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("os-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let receipt_id = receipt_id_at(3)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'open', NULL, 500)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    // The watermark must stop at 2 (below the aged receipt at entry 3), not
    // advance to 4 and delete the only live row the reconciliation can update.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below a receipt whose settlement reconciliation is still open"
    );

    let live = store.reader_connection_for_test()?;
    let settlement_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        settlement_live, 1,
        "the open reconciliation row must survive so a later reconciliation can update it"
    );
    let receipt_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        receipt_live, 1,
        "the receipt backing the open reconciliation must remain live for the upsert path"
    );
    drop(live);

    // The reconciliation reaches a terminal state; a later rotation now archives
    // the receipt and its reconciliation together.
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "UPDATE settlement_reconciliations SET reconciliation_state = 'reconciled', updated_at = 600 \
                 WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    let archived_again = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived_again, 2,
        "once the reconciliation is terminal the later rotation archives the [3,4] pair"
    );
    let live = store.reader_connection_for_test()?;
    let settlement_after: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        settlement_after, 0,
        "the terminal reconciliation archives with its receipt on the later rotation"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn rotation_rejects_unrecognized_reconciliation_states() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("invalid-reconciliation-state");
    let archive = unique_db_path("invalid-reconciliation-state-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("invalid-reconciliation-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let (first_receipt_id, second_receipt_id) = {
        let connection = store.reader_connection_for_test()?;
        (
            connection.query_row(
                "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = 1",
                [],
                |row| row.get::<_, String>(0),
            )?,
            connection.query_row(
                "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = 2",
                [],
                |row| row.get::<_, String>(0),
            )?,
        )
    };
    store.writer_handle().run_write({
        let first_receipt_id = first_receipt_id.clone();
        let second_receipt_id = second_receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations \
                 (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'corrupt-state', NULL, 1)",
                rusqlite::params![first_receipt_id],
            )?;
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, \
                  billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, \
                  note, updated_at) \
                 VALUES (?1, 'test', 'invalid-state-evidence', 1, 1, 'usd', NULL, 1, \
                         'corrupt-state', NULL, 1)",
                rusqlite::params![second_receipt_id],
            )?;
            Ok(())
        }
    })?;

    assert_eq!(
        store.archive_receipts_before(150, archive_path)?,
        0,
        "unrecognized reconciliation states must not be treated as terminal"
    );
    store.writer_handle().run_write({
        let first_receipt_id = first_receipt_id.clone();
        move |connection| {
            connection.execute(
                "UPDATE settlement_reconciliations \
                 SET reconciliation_state = 'reconciled' WHERE receipt_id = ?1",
                rusqlite::params![first_receipt_id],
            )?;
            Ok(())
        }
    })?;
    assert_eq!(
        store.archive_receipts_before(150, archive_path)?,
        0,
        "a corrupt metering state must independently block archival"
    );
    store.writer_handle().run_write(move |connection| {
        connection.execute(
            "UPDATE metered_billing_reconciliations \
             SET reconciliation_state = 'ignored' WHERE receipt_id = ?1",
            rusqlite::params![second_receipt_id],
        )?;
        Ok(())
    })?;
    assert_eq!(
        store.archive_receipts_before(150, archive_path)?,
        2,
        "the repaired terminal states permit the checkpointed prefix to archive"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The same pin applies to metered-billing reconciliations and to the
/// `retry_scheduled` state: an aged receipt whose metered-billing reconciliation
/// is still awaiting a scheduled retry must not be archived out from under the
/// row a later reconciliation attempt needs to resolve. Once the reconciliation
/// is terminal a later rotation archives the pair.
#[test]
fn rotation_preserves_receipt_with_scheduled_metered_reconciliation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("scheduled-metered-preserve");
    let archive = unique_db_path("scheduled-metered-preserve-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sm-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sm-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let receipt_id = receipt_id_at(3)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-sm', 1, 1, 'usd', NULL, 500, 'retry_scheduled', NULL, 500)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below a receipt whose metered-billing reconciliation is scheduled"
    );
    let live = store.reader_connection_for_test()?;
    let metered_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        metered_live, 1,
        "the scheduled reconciliation row must survive for the pending retry"
    );
    drop(live);

    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "UPDATE metered_billing_reconciliations SET reconciliation_state = 'ignored', updated_at = 600 \
                 WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    let archived_again = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived_again, 2,
        "once the reconciliation is terminal the later rotation archives the [3,4] pair"
    );
    let live = store.reader_connection_for_test()?;
    let metered_after: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        metered_after, 0,
        "the terminal reconciliation archives with its receipt on the later rotation"
    );

    drop(live);
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

/// A handle whose cached head is behind a checkpoint that a DIFFERENT handle
/// created and then archived must still report the archived boundary as
/// checkpointed. `flush` folds in the persisted latest checkpoint, but its live
/// claim-log rows were co-archived and deleted, so the persisted-checkpoint
/// validation must honor the archival watermark exemption (as the full chain
/// walk does). Without it flush discards the checkpoint and reports a stale
/// `checkpointed_entry_seq` with a spurious uncheckpointed range.
#[test]
fn flush_reports_watermark_covered_checkpoint_from_stale_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("flush-stale-head-watermark");
    let archive = unique_db_path("flush-stale-head-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Instance A checkpoints [1,2] and keeps its cached head at boundary 2.
    let store_a = SqliteReceiptStore::open(&path)?;
    store_a.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("fs-a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store_a.append_chio_receipt_returning_seq(&r)?;
    }
    store_a.flush_receipt_writes()?;
    assert!(store_a.load_checkpoint_by_seq(1)?.is_some());

    // A second instance appends [3,4], builds checkpoint 2 (boundary 4), then
    // archives the ENTIRE checkpointed history: every live claim-log row is
    // deleted and the watermark is set to 4. Instance A stays idle, so its cached
    // head never advances past boundary 2.
    {
        let store_b = SqliteReceiptStore::open_existing(&path)?;
        store_b.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 2..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("fs-b-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store_b.append_chio_receipt_returning_seq(&r)?;
        }
        store_b.flush_receipt_writes()?;
        assert!(store_b.load_checkpoint_by_seq(2)?.is_some());
        let archived = store_b.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the whole checkpointed history archives");
    }

    // Flush through the stale instance A. Its head sits at boundary 2, so the
    // report must fold in the persisted checkpoint 2 (boundary 4) even though the
    // live rows for its range are gone behind the watermark.
    let report = store_a.flush_receipt_writes()?;
    assert_eq!(
        report.latest_committed_entry_seq, 4,
        "committed progress folds in the archived prefix"
    );
    assert_eq!(
        report.latest_checkpointed_entry_seq, 4,
        "a watermark-covered persisted checkpoint must still be reported as checkpointed"
    );
    assert_eq!(
        report.uncheckpointed_start_seq, None,
        "a fully-checkpointed, fully-archived store has no uncheckpointed range"
    );
    assert_eq!(report.uncheckpointed_end_seq, None);

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
        insert_receipt_retention_watermark(
            connection,
            2,
            100,
            "phantom-archive.sqlite3",
            TEST_ARCHIVE_IDENTITY_SHA256,
            TEST_ARCHIVE_CONTENT_SHA256,
            1,
        )?;
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
    use std::os::unix::fs::PermissionsExt;

    let dir = unique_db_path("abs-archive-dir");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
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
