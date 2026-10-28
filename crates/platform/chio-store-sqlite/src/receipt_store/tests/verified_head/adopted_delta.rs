use super::*;

/// `append_receipt_batch` adopts every claim_receipt_log_entries row past a
/// STALE actor head as trusted baseline (the pre_delta), cross-checking only
/// the rows THIS batch inserts. A shared-DB out-of-band orphan/mismatched row
/// in that adopted range must not be blindly trusted: the batch validates JUST
/// that bounded delta range against the source tables. The single-writer
/// no-stale-head case (empty delta) adds no validation, so per-append cost
/// stays bounded by the batch, not total history.
#[test]
fn stale_head_validates_adopted_delta_before_trusting() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-stale-head-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Three real receipts -> claim-log entries 1..=3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-stale-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer commits an ORPHAN claim-log row (no source receipt)
    // at entry_seq 4. Inserts are not blocked by the reject_update trigger; the
    // CHECK constraint just requires the tool-receipt columns to be populated.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-oob-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // FAIL-CLOSED: a STALE head (claim_log_max_seq = 3) puts the orphan at
    // entry_seq 4 inside the adopted pre_delta. The append must be denied.
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: 3,
        claim_log_max_seq: 3,
    };
    let receipt = sample_receipt_with_keypair("rcpt-stale-append", 10, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _rx) = std::sync::mpsc::sync_channel(1);
    let requests = vec![ReceiptCommitRequest {
        receipt,
        raw_json,
        ensure_lineage: false,
        response,
    }];
    let error = append_receipt_batch(&store.pool, &mut stale_head, true, None, None, &requests)
        .err()
        .ok_or("stale-head append over an out-of-band orphan row must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "fail-closed Conflict must point at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // NO-OP: a FRESH head whose claim_log_max_seq already covers the orphan
    // (= 4) has an EMPTY delta, so the range validator does NOT re-scan the
    // below-floor orphan; appending a brand-new receipt succeeds.
    let mut fresh_head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: 4,
        claim_log_max_seq: 4,
    };
    let receipt = sample_receipt_with_keypair("rcpt-stale-fresh", 11, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _rx) = std::sync::mpsc::sync_channel(1);
    let requests = vec![ReceiptCommitRequest {
        receipt,
        raw_json,
        ensure_lineage: false,
        response,
    }];
    let results = append_receipt_batch(&store.pool, &mut fresh_head, true, None, None, &requests)?;
    assert!(
        results.iter().all(|result| result.is_ok()),
        "empty-delta append must add no validation and succeed: {results:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// `resync_head_after_write` advances the head after a Write closure by
/// COUNT/MAX over `claim_receipt_log_entries`. When another process (or a
/// receipt-appending Write job) commits rows PAST this actor's head, blindly
/// adopting them would trust an out-of-band orphan/divergent row that later
/// appends then skip as already-verified (a background checkpoint could then
/// cover an unaudited entry). Resync must validate JUST the adopted delta (the
/// same bounded `validate_adopted_claim_log_delta` the append path uses) before
/// advancing. The single-writer common case (empty delta) adds no validation,
/// so per-append cost stays bounded by the batch, not total history.
#[test]
fn resync_validates_adopted_delta() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-resync-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Three real receipts -> claim-log entries 1..=3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-resync-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer commits an ORPHAN claim-log row (no source receipt)
    // at entry_seq 4, past this actor's head. Same injection as the append-path
    // sibling above; inserts are not blocked by the reject_update trigger.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-resync-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // FAIL-CLOSED: a head at claim_log_max_seq = 3 puts the orphan at entry_seq 4
    // inside the adopted resync delta. The resync must REJECT it, not silently
    // absorb it, and must not advance the head.
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: 3,
        claim_log_max_seq: 3,
    };
    let connection = store.connection()?;
    let error = resync_head_after_write(&connection, &mut stale_head)
        .err()
        .ok_or("resync over an out-of-band orphan row must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "fail-closed Conflict must point at the audit CLI, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }
    assert_eq!(
        stale_head.claim_log_max_seq, 3,
        "a rejected resync must not adopt the divergent delta"
    );

    // NO-OP: a head already covering the orphan (max_seq = 4) has an EMPTY
    // resync delta, so the range validator does NOT re-scan the below-floor
    // orphan and the resync is a no-op.
    let mut fresh_head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: 4,
        claim_log_max_seq: 4,
    };
    resync_head_after_write(&connection, &mut fresh_head)?;
    assert_eq!(
        fresh_head.claim_log_max_seq, 4,
        "empty-delta resync must be a no-op"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// For a writer-routed Write job the actor must send the caller's result only
/// AFTER running `resync_head_after_write`. Because that resync can FAIL (it
/// poisons the head on a divergent adopted delta), a write whose closure
/// COMMITTED but whose resync then failed would otherwise return `Ok` while the
/// head was left poisoned. Deferring the response until after resync means a
/// committed write whose resync fails returns the resync error, not a stale
/// `Ok`.
#[test]
fn write_job_response_reflects_resync_failure() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-write-resync-fail");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Real receipts -> claim-log entries 1..=3, writer head at claim_log_max_seq 3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-wrf-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // A Write job whose closure COMMITS (returns Ok) but inserts an out-of-band
    // ORPHAN claim-log row at entry_seq 4 (no source receipt). The post-write
    // resync adopts (3, 4] as a delta, validates it, and REJECTS the orphan,
    // poisoning the head. The caller must receive that resync error, NOT Ok.
    let result: Result<(), ReceiptStoreError> =
        store.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT INTO claim_receipt_log_entries (
                    entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                    capability_id, tool_server, tool_name, raw_json
                ) VALUES (4, 'orphan-wrf-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
                "#,
                [],
            )?;
            Ok(())
        });

    let error = result
        .err()
        .ok_or("a committed Write whose resync fails must return the resync error, not Ok")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "resync failure must surface the fail-closed Conflict, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // Teeth: the resync failure poisoned the head, so the next write is denied.
    let next: Result<(), ReceiptStoreError> = store.writer_handle().run_write(|_connection| Ok(()));
    assert!(next.is_err(), "resync failure must poison the head");

    let _ = fs::remove_file(path);
    Ok(())
}

/// With incremental verification a RECEIPT-APPENDING writer-routed job (child
/// receipt / auth-consuming append) that pre-checked only the checkpoint head,
/// NOT the claim-log rows an out-of-band writer left AHEAD of this actor's
/// head, would let a bad/orphan `claim_receipt_log_entries` row present BEFORE
/// the job ran DURABLY insert its receipt and only THEN, in
/// `resync_head_after_write`, detect the orphan and poison the head (a
/// fail-OPEN durable write). Validating the adopted claim-log delta (the same
/// bounded `validate_adopted_claim_log_delta` the append path uses) BEFORE the
/// job runs denies the job with NO durable insert. The validation is
/// delta-bounded (an empty delta is the single-writer no-op), so per-append
/// cost stays bounded by the batch, not total history.
#[test]
fn writer_job_validates_adopted_delta_before_commit() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-writer-preval-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Real receipts -> claim-log entries 1..=3, writer head at claim_log_max_seq 3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-preval-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer leaves a bad/orphan claim-log row (no source receipt)
    // at entry_seq 4, AHEAD of this actor's head, BEFORE any writer job runs.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-preval-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // A RECEIPT-APPENDING writer job (`run_write_receipt`, appends_receipts =
    // true) whose closure would DURABLY insert a new claim-log row at entry_seq
    // 5. The pre-check must DENY the job because the adopted delta (3, 4] holds
    // the orphan, and the closure's row must never be durably inserted.
    let result: Result<(), ReceiptStoreError> =
        store.writer_handle().run_write_receipt(move |connection| {
            connection.execute(
                r#"
                INSERT INTO claim_receipt_log_entries (
                    entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                    capability_id, tool_server, tool_name, raw_json
                ) VALUES (5, 'writer-job-row-5', 'tool_receipt', 5, 1, 'cap-job', 'shell', 'bash', '{}')
                "#,
                [],
            )?;
            Ok(())
        });

    let error = result
        .err()
        .ok_or("a receipt-appending writer job over a pre-existing orphan must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "fail-closed Conflict must point at the audit CLI, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // TEETH: the job's row must be rejected BEFORE the durable insert. A
    // post-commit resync check would let the closure run and persist entry_seq
    // 5 before rejecting; the pre-check denies the job so entry_seq 5 never
    // exists.
    let connection = store.connection()?;
    let job_row: i64 = connection.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq = 5",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        job_row, 0,
        "the writer job's receipt must NOT be durably inserted when a pre-existing orphan blocks the adopted baseline"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// On the same-seq fast path `verify_head_against_latest_checkpoint` compares
/// the RFC 8785 body digest (statement_json) plus the signature/kernel_key
/// columns. The kernel_checkpoints row ALSO stores batch_start_seq/
/// batch_end_seq/tree_size/merkle_root/issued_at as their own columns; a
/// signed-body-bound column tampered out of band while statement_json is
/// untouched would pass a digest-only check. Reconciling EVERY such column
/// against the signed body (`ensure_checkpoint_columns_match_body`, O(1) over
/// one row, no Ed25519) makes the column tamper fail closed.
#[test]
fn head_trust_checks_all_checkpoint_columns() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path, store, keypair) = open_seeded_store("chio-head-allcols", 3)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Baseline: an untouched same-seq checkpoint verifies clean on the fast path.
    verify_head_against_latest_checkpoint(&connection, &mut head)?;

    // Tamper a SIGNED-BODY integrity COLUMN (batch_end_seq) out of band while
    // leaving statement_json (and thus the body digest) intact, bypassing the
    // immutability trigger. The digest branch alone would accept this.
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    let tampered = connection.execute(
        "UPDATE kernel_checkpoints SET batch_end_seq = batch_end_seq + 1 WHERE checkpoint_seq = 1",
        [],
    )?;
    assert_eq!(tampered, 1, "expected to tamper exactly one checkpoint row");

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("a tampered signed-body column must be rejected on the fast path")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("batch_end_seq"),
                "Conflict should name the tampered column, got: {message}"
            );
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// `validate_adopted_claim_log_delta` that iterated only the claim-log rows
/// that CURRENTLY EXIST in the adopted range would let an interior GAP (a
/// missing entry_seq) pass unnoticed. The adopted range must therefore be
/// CONTIGUOUS (floor+1..=max with no hole), an O(delta) ordered scan over the
/// already-loaded delta, rejecting fail-closed on a gap while a contiguous
/// delta still passes.
#[test]
fn adopted_delta_rejects_interior_gap() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-adopted-delta-gap");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Four real, correctly-projecting receipts -> contiguous claim-log entries
    // 1,2,3,4. Every row projects from its source receipt, so the projection
    // cross-check alone cannot fail; only the contiguity rule can.
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-gap-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let connection = store.connection()?;

    // Contiguous delta (0, 4] = {1,2,3,4}: every row present and projecting, so
    // the validator accepts it.
    validate_adopted_claim_log_delta(&connection, 0, 4)?;

    // Punch an INTERIOR hole: delete entry_seq 3 (drop the append-only trigger
    // first), leaving {1,2,4}. The three surviving rows still project cleanly.
    connection.execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")?;
    let deleted = connection.execute(
        "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 3",
        [],
    )?;
    assert_eq!(deleted, 1, "expected to remove exactly one claim-log row");

    // Now (0, 4] = {1,2,4} is non-contiguous. Without the contiguity check the
    // projection loop would accept the surviving rows and return Ok; the
    // contiguity scan detects the gap at entry_seq 3 and fails closed.
    let error = validate_adopted_claim_log_delta(&connection, 0, 4)
        .err()
        .ok_or("a non-contiguous adopted delta must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("not contiguous") && message.contains('3'),
                "Conflict should identify the interior gap, got: {message}"
            );
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// The watermark ledger's DB triggers enforce monotonicity but not archival, so
/// a raw INSERT can plant a high but bogus watermark while the covered rows stay
/// live. `validate_adopted_claim_log_delta` must raise its contiguity floor only
/// to the TRUSTED watermark; trusting the raw value would let a delta at or below
/// the bogus mark short-circuit before the contiguity and projection checks,
/// silently adopting corrupted claim-log rows. Here rows {1,2,4} are live (an
/// interior hole at 3) and a bogus watermark of 4 is planted without archiving;
/// the validator must still fail closed on the gap because the watermark is not
/// trustworthy.
#[test]
fn adopted_delta_ignores_untrusted_watermark() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-adopted-delta-bogus-watermark");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bogus-wm-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let connection = store.connection()?;

    // Punch an interior hole: delete entry_seq 3, leaving a non-contiguous
    // {1,2,4}. The three survivors still project cleanly, so only the contiguity
    // scan can reject the delta.
    connection.execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")?;
    let deleted = connection.execute(
        "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 3",
        [],
    )?;
    assert_eq!(deleted, 1, "expected to remove exactly one claim-log row");

    // Plant a bogus watermark of 4 without archiving anything: the rows covered
    // by it are still live. The monotonicity trigger accepts it as the first
    // mark. A raw watermark floor would lift the effective floor to 4 and, since
    // the delta max (4) equals it, return early before validating the range.
    connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, rotated_at) \
         VALUES (4, 0, '', 0)",
        [],
    )?;

    // Because the covered prefix is still live, the watermark is untrusted, so
    // the floor stays at 0 and the contiguity scan detects the hole at entry_seq
    // 3, failing closed.
    let error = validate_adopted_claim_log_delta(&connection, 0, 4)
        .err()
        .ok_or("an untrusted watermark must not let a non-contiguous delta pass")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("not contiguous") && message.contains('3'),
                "Conflict should identify the interior gap, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}
