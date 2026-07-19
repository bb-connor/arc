/// Writer-actor head snapshot exposed to `flush_report` and diagnostics.
/// Values are read from the health struct's atomics, written
/// only by the actor thread.
pub(crate) struct WriterHeadSnapshot {
    pub(crate) checkpoint_seq: u64,
    pub(crate) checkpointed_entry_seq: u64,
    // Read only by tests (`incremental_append_updates_the_head_and_stays_correct`,
    // `writer_routed_inserts_do_not_false_conflict_the_next_append`): they
    // cross-check the actor-maintained head against a full re-verification.
    // `flush_report` does not need the claim-log counters today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) claim_log_count: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) claim_log_max_seq: u64,
}

/// Seed the verified head by running the existing FULL verification exactly
/// once (the startup path for the O(N) check; also the audit-repair path).
fn seed_verified_head(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    validate_claim_receipt_log_entries(connection)?;
    let latest_checkpoint = verify_checkpoint_chain_integrity(connection)?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}

/// Cheap head snapshot for `incremental_verification = false` stores: the
/// full per-append verification still runs on that path, so seeding only
/// parses the single latest checkpoint row (one signature check) plus two
/// aggregates. This keeps a suspect database openable for A/B verification.
fn seed_head_snapshot(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    let latest_checkpoint = load_latest_persisted_checkpoint_row(connection)?
        .map(parse_persisted_checkpoint_row)
        .transpose()?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}

/// COUNT/MAX over `entry_seq > floor_entry_seq`: an indexed range scan over
/// the delta only (O(b)). An unscoped COUNT(*) would rescan the whole index
/// and reintroduce O(N). Returns `(delta_count, max_entry_seq)` where the max
/// falls back to `floor_entry_seq` for an empty delta.
fn claim_log_delta_count_and_max_seq(
    connection: &Connection,
    floor_entry_seq: u64,
) -> Result<(u64, u64), ReceiptStoreError> {
    let floor = sqlite_i64(floor_entry_seq, "claim log delta floor entry_seq")?;
    let (count, max_seq) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(entry_seq), ?1) FROM claim_receipt_log_entries WHERE entry_seq > ?1",
        params![floor],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok((
        sqlite_u64(count, "claim log delta count")?,
        sqlite_u64(max_seq, "claim log delta max entry_seq")?,
    ))
}

/// Fail-closed pre-job guard for a RECEIPT-APPENDING writer-routed job (child
/// receipts, authorization-consuming appends). The
/// incremental writer pre-check only re-verified the checkpoint HEAD; it did
/// NOT validate the `claim_receipt_log_entries` rows an out-of-band writer (a
/// second store instance, an operator repair) may have committed AHEAD of this
/// actor's head. Without this guard the job would DURABLY insert its receipt
/// and only afterwards, in `resync_head_after_write`, discover the bad/orphan
/// adopted row and poison the head - a fail-OPEN durable write. Validate the
/// ADOPTED delta (head.claim_log_max_seq, current_max] with the SAME bounded
/// `validate_adopted_claim_log_delta` the append path runs, BEFORE the job
/// commits, so a stale/invalid baseline denies the write with no durable
/// insert. Delta-bounded: single-writer no-stale-head case has an EMPTY delta
/// (pre_delta = 0) and is a no-op, and the full-log validator is NEVER called,
/// so the flat per-append cost holds. Metadata-only writes insert no
/// claim-log rows, so they skip this (appends_receipts = false).
fn validate_writer_adopted_claim_log_baseline(
    connection: &Connection,
    head: &VerifiedHead,
    appends_receipts: bool,
) -> Result<(), ReceiptStoreError> {
    if !appends_receipts {
        return Ok(());
    }
    let (pre_delta, baseline_max) =
        claim_log_delta_count_and_max_seq(connection, head.claim_log_max_seq)?;
    if pre_delta > 0 {
        validate_adopted_claim_log_delta(connection, head.claim_log_max_seq, baseline_max)?;
    }
    Ok(())
}

/// O(1) predecessor check: the persisted latest checkpoint must still match
/// the verified head (one indexed row read + RFC 8785 canonical body digest
/// compare). When the persisted chain has moved FORWARD, verify only the new
/// checkpoints (bounded catch-up); every other divergence is a fail-closed
/// `Conflict` pointing at `chio receipt audit`.
fn verify_head_against_latest_checkpoint(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let persisted = load_latest_persisted_checkpoint_row(connection)?;
    let cached_seq = head.checkpoint_seq();
    match persisted {
        None if head.latest_checkpoint.is_none() => Ok(()),
        None => Err(ReceiptStoreError::Conflict(
            "latest checkpoint disappeared behind the verified head; run `chio receipt audit`"
                .to_string(),
        )),
        Some(row) if row.checkpoint_seq < cached_seq => Err(ReceiptStoreError::Conflict(format!(
            "checkpoint chain regressed from verified head {cached_seq} to {}; run `chio receipt audit`",
            row.checkpoint_seq
        ))),
        Some(row) if row.checkpoint_seq == cached_seq => {
            let Some(cached) = head.latest_checkpoint.as_ref() else {
                return Err(ReceiptStoreError::Conflict(
                    "checkpoint presence diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            };
            // Body-only deserialize: parse_persisted_checkpoint_row would run
            // chio_kernel::checkpoint::validate_checkpoint and re-verify the
            // signature, putting one Ed25519 verify back on every append. The
            // cached head was signature-checked at seed time.
            let persisted_body: KernelCheckpointBody = serde_json::from_str(&row.statement_json)?;
            let persisted_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&persisted_body)
                .map_err(checkpoint_error_to_receipt_store)?;
            let cached_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&cached.body)
                .map_err(checkpoint_error_to_receipt_store)?;
            if persisted_digest != cached_digest {
                return Err(ReceiptStoreError::Conflict(
                    "latest checkpoint diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            }
            // Full-column tamper catch: the body digest above covers ONLY what
            // statement_json serializes. The kernel_checkpoints row also stores
            // batch_start_seq/batch_end_seq/tree_size/merkle_root/issued_at/
            // kernel_key as their own columns; any one of them corrupted out of
            // band (immutability trigger bypassed) while statement_json is
            // untouched would pass the digest check yet leave a signed-body-bound
            // column diverged. `ensure_checkpoint_columns_match_body` reconciles
            // every such column against the (signature-verified) signed body it
            // is meant to mirror. This is O(1) int/string equality over the one
            // already-read row, NOT a per-append Ed25519 re-verify.
            ensure_checkpoint_columns_match_body(&row, &persisted_body)?;
            // The `signature` column is the signature OVER the body, not a body
            // field, so it is not covered above; compare it against the cached
            // head, which was signature-verified at seed/catch-up time (O(1)
            // string equality, no crypto).
            if row.signature_hex != cached.signature.to_hex() {
                return Err(ReceiptStoreError::Conflict(
                    "latest checkpoint signature column diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            }
            // Recheck the latest checkpoint's transparency projection rows.
            // The body-digest / column / signature
            // checks above re-verify the `kernel_checkpoints` row on every
            // append, but the projection rows (`checkpoint_tree_heads`,
            // `checkpoint_predecessor_witnesses`,
            // `checkpoint_publication_metadata`) were validated only when this
            // checkpoint was first adopted (seed or catch-up). A projection row
            // tampered out of band (immutability guards momentarily absent, then
            // restored) while the checkpoint seq is UNCHANGED would otherwise be
            // trusted as verified until the next open/health/audit. Rechecking it
            // here closes that gap symmetrically with the per-append column
            // recheck: O(1) (three indexed single-row projection lookups plus an
            // O(1) derivation from the already-parsed checkpoint body, NO
            // batch/leaf scan and NO full-history walk), so the incremental
            // hot path stays flat per append. Fail-closed on any divergence.
            validate_checkpoint_projection_rows(connection, &row, cached)?;
            Ok(())
        }
        Some(row) => catch_up_verified_head_to(connection, head, row.checkpoint_seq),
    }
}

/// Verify and adopt checkpoints `head.checkpoint_seq()+1 ..= latest_seq`.
/// O(new checkpoints): each row is parsed (one signature check), predecessor-
/// linked to the cached head, range-checked against the claim log, AND its
/// transparency projection rows validated before it
/// advances the head. Used when another writer instance (second kernel on the
/// same file, operator CLI) legitimately extended the chain. In the single-
/// writer hot path the head is never behind, so this loop body does not run
/// (zero added per-append cost); each caught-up checkpoint is O(b) for its own
/// batch, never a full-history walk.
fn catch_up_verified_head_to(
    connection: &Connection,
    head: &mut VerifiedHead,
    latest_seq: u64,
) -> Result<(), ReceiptStoreError> {
    let mut cursor = head.checkpoint_seq();
    while cursor < latest_seq {
        let next_seq = cursor.saturating_add(1);
        let Some(row) = load_persisted_checkpoint_row(connection, next_seq)? else {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint chain gap at {next_seq} behind latest {latest_seq}; run `chio receipt audit`"
            )));
        };
        let checkpoint = parse_persisted_checkpoint_row(row.clone())?;
        match head.latest_checkpoint.as_ref() {
            Some(predecessor) => {
                chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                    .map_err(checkpoint_error_to_receipt_store)?;
            }
            None => validate_checkpoint_base(&checkpoint)?,
        }
        validate_checkpoint_against_claim_log(connection, &checkpoint)?;
        // Projection validation before adoption: the
        // catch-up path verified signature + predecessor + claim-log range but
        // not the transparency projection rows that full
        // `verify_checkpoint_chain_integrity` rejects. Adopting a checkpoint with
        // missing/divergent projection rows would advance `head.latest_checkpoint`
        // and let subsequent appends build on an audit-invalid chain. Validate ONLY
        // this adopted checkpoint's projection rows (O(b) for its batch, not full
        // history), fail closed on any divergence.
        validate_checkpoint_projection_rows(connection, &row, &checkpoint)?;
        head.latest_checkpoint = Some(checkpoint);
        cursor = next_seq;
    }
    Ok(())
}

/// Insert one receipt (and, when requested, its lineage statement) within the
/// caller's transaction, returning the claim-log `entry_seq`. Split out of
/// `append_receipt_batch` so each record can run inside its own SAVEPOINT: a
/// per-receipt failure is returned as this record's `Err`
/// instead of aborting the whole coalesced batch. Receipt + lineage stay one
/// unit - a lineage failure returns `Err`, and the caller's savepoint rollback
/// undoes the receipt too, so no receipt-without-lineage state is possible.
fn append_single_receipt_record(
    tx: &rusqlite::Transaction<'_>,
    request: &ReceiptCommitRequest,
) -> Result<u64, ReceiptStoreError> {
    let seq = append_chio_receipt_tx(tx, &request.receipt, &request.raw_json)?;
    if request.ensure_lineage {
        #[cfg(test)]
        if test_hooks::fail_between_receipt_and_lineage() {
            return Err(ReceiptStoreError::Conflict(
                "injected failure between receipt insert and lineage insert".to_string(),
            ));
        }
        ensure_receipt_lineage_statement_for_receipt_id_tx(tx, &request.receipt.id)?;
    }
    Ok(seq)
}

fn append_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    incremental_verification: bool,
    requests: &[ReceiptCommitRequest],
) -> Vec<Result<u64, ReceiptStoreError>> {
    let mut connection = match pool.get() {
        Ok(connection) => connection,
        Err(error) => {
            return receipt_batch_error_results(
                requests.len(),
                ReceiptStoreError::Pool(error.to_string()),
            );
        }
    };
    if let Err(error) = ensure_checkpoint_transparency_guards(&connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    if incremental_verification {
        // O(1) predecessor check (+ bounded catch-up), not a chain rebuild.
        if let Err(error) = verify_head_against_latest_checkpoint(&connection, head) {
            return receipt_batch_error_results(requests.len(), error);
        }
    } else if let Err(error) = validate_claim_receipt_log_entries(&connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    let tx = match connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => {
            return receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error));
        }
    };
    if !incremental_verification {
        if let Err(error) = verify_latest_checkpoint_integrity(&tx) {
            return receipt_batch_error_results(requests.len(), error);
        }
    }
    // Baseline inside the IMMEDIATE tx: rows another store instance committed
    // since our last look are adopted as pre-existing, so the cross-check
    // below measures exactly what THIS batch inserted.
    let (pre_delta, baseline_max) =
        match claim_log_delta_count_and_max_seq(&tx, head.claim_log_max_seq) {
            Ok(pair) => pair,
            Err(error) => return receipt_batch_error_results(requests.len(), error),
        };
    // Validate the ADOPTED baseline delta before trusting it. Rows another
    // store instance committed since our last look
    // (head.claim_log_max_seq + 1 ..= baseline_max) are absorbed as
    // pre-existing baseline. A full per-append validation would reject an
    // out-of-band mismatched/orphan claim_receipt_log_entries row
    // in that range. Re-validate JUST that bounded delta against the source
    // receipt tables (O(delta)); the full-log validator is NOT called. In the
    // single-writer hot path the head is never stale, so pre_delta is 0 and
    // this is a no-op (zero added cost).
    if pre_delta > 0 {
        if let Err(error) =
            validate_adopted_claim_log_delta(&tx, head.claim_log_max_seq, baseline_max)
        {
            return receipt_batch_error_results(requests.len(), error);
        }
    }
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        #[cfg(test)]
        if test_hooks::panic_during_append_batch(&request.receipt.content_hash) {
            panic!("injected test panic during append batch");
        }
        // Per-record SAVEPOINT: a coalesced group-commit
        // batch mixes independent producers. A per-receipt failure (a conflicting
        // duplicate raw JSON, a lineage insert failure) must fail ONLY that
        // record, not roll back and error every unrelated valid append sharing
        // the same group-commit window. Wrap each record so a failure ROLLBACK TO
        // the savepoint undoes JUST this record's partial work - its receipt row,
        // its projection-trigger claim-log row, and its AUTOINCREMENT entry_seq,
        // which SQLite restores with the savepoint so surviving rows stay
        // contiguous - and the loop continues with the others. Two extra SQL
        // statements per record: O(1) per record, O(b) per batch, never a
        // full-history scan, so the flat per-append cost holds.
        if let Err(error) = tx.execute_batch("SAVEPOINT chio_append_record") {
            return receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error));
        }
        match append_single_receipt_record(&tx, request) {
            Ok(seq) => {
                if let Err(error) = tx.execute_batch("RELEASE chio_append_record") {
                    return receipt_batch_error_results(
                        requests.len(),
                        ReceiptStoreError::Sqlite(error),
                    );
                }
                results.push(Ok(seq));
            }
            Err(error) => {
                // Fail THIS record closed and undo only its work, then keep going
                // for the others. A savepoint that will not unwind is a
                // transaction-integrity fault, so fail the whole batch closed in
                // that (unexpected) case.
                if let Err(rollback) =
                    tx.execute_batch("ROLLBACK TO chio_append_record; RELEASE chio_append_record")
                {
                    return receipt_batch_error_results(
                        requests.len(),
                        ReceiptStoreError::Sqlite(rollback),
                    );
                }
                results.push(Err(error));
            }
        }
    }
    // Idempotent duplicates return the existing entry_seq without adding a
    // projection row (append_chio_receipt_tx: ON CONFLICT(receipt_id) DO
    // NOTHING at receipt_store.rs:972, byte-identical duplicate branch at
    // :992-1011). Only entry_seqs beyond the baseline count as new rows, and
    // only DISTINCT ones: two byte-identical receipts landing in a single
    // group-commit batch (a concurrent duplicate append) both return the SAME
    // entry_seq from the idempotent branch while inserting exactly one
    // projection row. Deduplicating the new seqs keeps `inserted` equal to the
    // distinct row count so the cross-check below does not false-trigger the
    // projection-drift Conflict and roll back a valid idempotent batch.
    let inserted = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .filter(|seq| **seq > baseline_max)
        .copied()
        .collect::<std::collections::BTreeSet<u64>>()
        .len() as u64;
    // O(b) projection cross-check over the delta only: the claim-log
    // projection triggers (bootstrap/open.rs:676 tool, :711 child) must have
    // advanced the projection by exactly the rows this batch inserted.
    let (delta_count, post_max) = match claim_log_delta_count_and_max_seq(&tx, baseline_max) {
        Ok(pair) => pair,
        Err(error) => return receipt_batch_error_results(requests.len(), error),
    };
    if delta_count != inserted || post_max < baseline_max {
        return receipt_batch_error_results(
            requests.len(),
            ReceiptStoreError::Conflict(
                "claim receipt log projection drift on append; run `chio receipt audit`"
                    .to_string(),
            ),
        );
    }
    // Validate the NEWLY-projected rows before advancing the head. The
    // count/MAX cross-check above only proves the projection
    // advanced by the right NUMBER of rows; `append_chio_receipt_tx` verifies
    // only the projected `receipt_id`/`raw_json`, so a tampered projection
    // trigger could emit one row per insert whose `timestamp`, `tool_name`, or
    // attribution columns diverge from the source receipt and still pass here.
    // A full per-append validation would reject that drift on the next
    // append; without validating it now the head advances and future
    // appends treat the bad row as already verified. Re-validate JUST the
    // (baseline_max, post_max] delta this batch projected with the same
    // full-field validator (O(delta): the batch inserts a bounded number of
    // rows, so the flat per-append cost holds and the full-log validator is
    // NEVER called). Gated on a non-empty delta (an all-idempotent
    // batch projects nothing, so this is a no-op). Fail-closed: a divergent row
    // returns the Conflict before `tx.commit()`, so the head never advances.
    if delta_count > 0 {
        if let Err(error) = validate_adopted_claim_log_delta(&tx, baseline_max, post_max) {
            return receipt_batch_error_results(requests.len(), error);
        }
    }
    match tx.commit() {
        Ok(()) => {
            head.claim_log_count = head
                .claim_log_count
                .saturating_add(pre_delta)
                .saturating_add(delta_count);
            head.claim_log_max_seq = post_max.max(baseline_max);
            results
        }
        Err(error) => receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error)),
    }
}

fn receipt_batch_error_results(
    count: usize,
    error: ReceiptStoreError,
) -> Vec<Result<u64, ReceiptStoreError>> {
    let snapshot = receipt_store_error_snapshot(&error);
    let mut original = Some(error);
    (0..count)
        .map(|_| {
            Err(original
                .take()
                .unwrap_or_else(|| receipt_store_error_snapshot(&snapshot)))
        })
        .collect()
}

fn receipt_store_error_snapshot(error: &ReceiptStoreError) -> ReceiptStoreError {
    match error {
        ReceiptStoreError::Sqlite(error) => {
            ReceiptStoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::other(error.to_string()),
            )))
        }
        ReceiptStoreError::Pool(message) => ReceiptStoreError::Pool(message.clone()),
        ReceiptStoreError::Timeout {
            operation,
            timeout_ms,
        } => ReceiptStoreError::Timeout {
            operation: operation.clone(),
            timeout_ms: *timeout_ms,
        },
        ReceiptStoreError::Json(error) => ReceiptStoreError::Json(serde_json::Error::io(
            std::io::Error::other(error.to_string()),
        )),
        ReceiptStoreError::Io(error) => {
            ReceiptStoreError::Io(std::io::Error::new(error.kind(), error.to_string()))
        }
        ReceiptStoreError::CryptoDecode(message) => {
            ReceiptStoreError::CryptoDecode(message.clone())
        }
        ReceiptStoreError::Canonical(message) => ReceiptStoreError::Canonical(message.clone()),
        ReceiptStoreError::InvalidOutcome(message) => {
            ReceiptStoreError::InvalidOutcome(message.clone())
        }
        ReceiptStoreError::ReadBoundary(message) => {
            ReceiptStoreError::ReadBoundary(message.clone())
        }
        ReceiptStoreError::Conflict(message) => ReceiptStoreError::Conflict(message.clone()),
        ReceiptStoreError::NotFound(message) => ReceiptStoreError::NotFound(message.clone()),
    }
}

/// Convert a caught panic payload into a typed, fail-closed error. Panic
/// payloads are almost always `&'static str` (a `panic!("literal")`) or
/// `String` (a formatted `panic!("{}", ..)`); anything else degrades to a
/// generic message rather than unwrapping (house rule: no unwrap/expect in
/// non-test code).
fn receipt_writer_job_panic_error(payload: &(dyn std::any::Any + Send)) -> ReceiptStoreError {
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string());
    ReceiptStoreError::Canonical(format!("receipt writer job panicked: {message}"))
}

/// Panic isolation: `commit_receipt_batch`
/// runs on the single writer thread, so a panic anywhere inside it (append
/// transaction, lineage fold) must not kill that thread. By the time this
/// runs, `requests` has already been moved into the panicking call and dropped
/// during unwind, so the pre-cloned request response senders are the only way
/// left to answer every appender in the batch. The co-drained Flush waiters are
/// NOT moved into the panicking call: they survive
/// the unwind in the actor loop, which fans out the returned error to them
/// after this. This mirrors `receipt_batch_error_results`'s uniform fan-out and
/// the health bookkeeping `commit_receipt_batch` would otherwise have performed
/// itself.
fn fan_out_batch_panic_error(
    health: &ReceiptCommitWriterHealth,
    request_responses: Vec<mpsc::SyncSender<Result<u64, ReceiptStoreError>>>,
    error: ReceiptStoreError,
) -> ReceiptStoreError {
    let batch_len = request_responses.len() as u64;
    health.failed_total.fetch_add(batch_len, Ordering::SeqCst);
    atomic_saturating_sub(&health.inflight, batch_len);
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = Some(error.to_string());
    }
    for response in request_responses {
        let _ = response.send(Err(receipt_store_error_snapshot(&error)));
    }
    error
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// When set, `append_receipt_batch` fails the batch between the receipt
    /// insert and the lineage ensure, proving the fold is one transaction.
    pub(crate) static FAIL_BETWEEN_RECEIPT_AND_LINEAGE: AtomicBool = AtomicBool::new(false);

    pub(crate) fn fail_between_receipt_and_lineage() -> bool {
        FAIL_BETWEEN_RECEIPT_AND_LINEAGE.load(Ordering::SeqCst)
    }

    /// When set, `maybe_build_checkpoint` panics after computing the
    /// checkpoint body but before opening its write transaction, proving the
    /// background-checkpoint catch_unwind wrap keeps the writer actor alive
    /// and leaves `head.latest_checkpoint` unadvanced. Tests run in parallel
    /// within this binary and this flag is process-global, so the panic is
    /// additionally gated on `PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH`
    /// (a `max_batch` value no other test in this crate uses): a test whose
    /// signer does not use that exact batch size never panics, even if the
    /// flag happens to be `true` while it runs.
    pub(crate) static PANIC_DURING_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

    pub(crate) const PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 5;

    pub(crate) fn panic_during_checkpoint_build(max_batch: u64) -> bool {
        max_batch == PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH
            && PANIC_DURING_CHECKPOINT_BUILD.load(Ordering::SeqCst)
    }

    /// When set, `maybe_build_checkpoint` returns a fail-closed `Err` (a
    /// NON-panic checkpoint-build failure) for a signer using
    /// `FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH`, proving a build failure is
    /// surfaced to a co-drained flush waiter (the flush-as-checkpoint
    /// barrier). It uses a DISTINCT marker from
    /// `PANIC_DURING_CHECKPOINT_BUILD` so the two process-global flags cannot
    /// interfere across the crate's parallel tests.
    pub(crate) static FAIL_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

    pub(crate) const FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 7;

    pub(crate) fn fail_checkpoint_build(max_batch: u64) -> bool {
        max_batch == FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH
            && FAIL_CHECKPOINT_BUILD.load(Ordering::SeqCst)
    }

    /// When set, `append_receipt_batch` panics before inserting the next
    /// request in the batch, proving the append-batch catch_unwind wrap in
    /// `receipt_commit_actor_loop` keeps the writer actor alive and fans out
    /// a typed error to every request in the interrupted batch. Gated on a
    /// `content_hash` marker for the same cross-test isolation reason as
    /// `PANIC_DURING_CHECKPOINT_BUILD` above (this flag is process-global,
    /// and other tests append receipts concurrently in the same binary).
    /// `content_hash`, not `receipt.id`, is the marker: `ChioReceipt::sign`
    /// always overwrites `id` with a content-derived hash
    /// (`prepare_receipt_body_for_signing`), so a caller-chosen `id` string
    /// does not survive signing, but a caller-chosen `content_hash` does.
    pub(crate) static PANIC_DURING_APPEND_BATCH: AtomicBool = AtomicBool::new(false);

    pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID: &str =
        "rcpt-test-hook-panic-during-append-batch";

    /// `sample_receipt_with_id(id)` sets `content_hash: format!("content-{id}")`;
    /// this must match that pattern for `PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID`.
    pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH: &str =
        "content-rcpt-test-hook-panic-during-append-batch";

    pub(crate) fn panic_during_append_batch(content_hash: &str) -> bool {
        content_hash == PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH
            && PANIC_DURING_APPEND_BATCH.load(Ordering::SeqCst)
    }
}


use support::*;
pub(crate) use support::{decode_verified_child_receipt, decode_verified_chio_receipt, sqlite_u64};

impl SqliteReceiptStore {
    /// Reader-pool connection. READS ONLY: every write transaction must go
    /// through `writer_handle().run_write` (single-writer discipline). The
    /// reader pool is asserted read-only by
    /// `reader_pool_never_begins_a_write_transaction` in tests.
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.database_identity_file.validate()?;
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    pub(crate) fn writer_handle(&self) -> WriterHandle {
        WriterHandle {
            sender: self.receipt_commit_actor.sender.clone(),
            health: Arc::clone(&self.receipt_commit_actor.health),
            database_identity_file: Some(Arc::clone(&self.database_identity_file)),
        }
    }

    /// Highest tool-receipt replication seq, or 0 on an empty store. Single
    /// indexed MAX read; does not materialize the store.
    pub fn max_tool_receipt_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Highest child-receipt replication seq, or 0 on an empty store.
    pub fn max_child_receipt_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_child_receipts",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Multi-tenant receipt isolation: toggle strict-isolation
    /// mode on tenant-scoped queries.
    ///
    /// When `strict = true`, a `tenant_filter = Some(id)` query returns
    /// ONLY rows whose `tenant_id = id`. Pre-multitenant receipts with
    /// `tenant_id IS NULL` are excluded.
    ///
    /// When `strict = false`, the same query also includes rows where
    /// `tenant_id IS NULL` -- the pre-multitenant "public" fallback
    /// set -- so pre-multitenant (NULL-tagged) receipts remain visible during
    /// an explicit compatibility window.
    ///
    /// A `tenant_filter = None` admin / compat query always returns
    /// every row regardless of this setting.
    pub fn with_strict_tenant_isolation(&self, strict: bool) {
        self.strict_tenant_isolation
            .store(strict, std::sync::atomic::Ordering::SeqCst);
    }

    /// Read the current strict-tenant-isolation setting.
    #[must_use]
    pub fn strict_tenant_isolation_enabled(&self) -> bool {
        self.strict_tenant_isolation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Read-only after open (staged-rollout flag).
    #[must_use]
    pub fn incremental_verification_enabled(&self) -> bool {
        self.incremental_verification
    }

    pub(crate) fn writer_head_snapshot(&self) -> WriterHeadSnapshot {
        let health = &self.receipt_commit_actor.health;
        WriterHeadSnapshot {
            checkpoint_seq: health.head_checkpoint_seq.load(Ordering::SeqCst),
            checkpointed_entry_seq: health.head_checkpointed_entry_seq.load(Ordering::SeqCst),
            claim_log_count: health.head_claim_log_count.load(Ordering::SeqCst),
            claim_log_max_seq: health.head_claim_log_max_seq.load(Ordering::SeqCst),
        }
    }

    pub fn append_chio_receipt_canonical(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
            .map(|_| ())
    }

    pub fn append_chio_receipt_canonical_bytes(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical(canonical)
    }

    pub fn append_chio_receipt_canonical_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        let receipt = decode_canonical_chio_receipt(canonical.as_ref())?;
        let raw_json = canonical_receipt_json(canonical.as_ref())?;
        self.append_verified_chio_receipt_record(&receipt, raw_json, false)
    }

    pub fn append_chio_receipt_canonical_bytes_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
    }

    fn append_verified_chio_receipt_record(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor
            .append(receipt.clone(), raw_json.to_string(), ensure_lineage)
    }

    pub fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        if receipt.id != consumption.consumer_receipt_id {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption consumer receipt id does not match appended receipt"
                    .to_string(),
            ));
        }
        if receipt.tenant_id.as_deref() != consumption.tenant_id.as_deref() {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption tenant id does not match appended receipt".to_string(),
            ));
        }
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        let raw_json = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let raw_json = std::str::from_utf8(raw_json.as_slice()).map_err(|error| {
            ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
        })?;
        let raw_json = raw_json.to_string();
        let receipt = receipt.clone();
        let consumption = consumption.clone();
        self.writer_handle().run_write_receipt(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            consume_authorization_receipt_tx(&tx, &consumption)?;
            append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn append_indexed_security_evidence(
        &self,
        evidence_id: &OpaqueReceiptRef,
        receipt: &ChioReceipt,
    ) -> Result<ChioReceipt, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        validate_indexed_security_receipt(evidence_id, receipt)?;
        let raw_json = serde_json::to_string(receipt)?;
        let evidence_id = evidence_id.as_str().to_string();
        let receipt = receipt.clone();
        self.writer_handle().run_write_receipt(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some(existing_raw_json) = tx
                .query_row(
                    r#"
                    SELECT receipt.raw_json
                    FROM chio_security_evidence_index AS evidence
                    JOIN chio_tool_receipts AS receipt
                      ON receipt.receipt_id = evidence.receipt_id
                    WHERE evidence.evidence_id = ?1
                    "#,
                    params![evidence_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                let existing = decode_verified_chio_receipt(
                    &existing_raw_json,
                    "indexed active-defense receipt",
                    None,
                )?;
                if !same_unsigned_receipt_and_bbs_binding(&existing, &receipt)? {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "active-defense evidence `{evidence_id}` is already mapped to a different receipt"
                    )));
                }
                tx.commit()?;
                return Ok(existing);
            }

            let existing_for_receipt = tx
                .query_row(
                    "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                    params![receipt.id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|existing_raw_json| {
                    decode_verified_chio_receipt(
                        &existing_raw_json,
                        "preexisting active-defense receipt",
                        None,
                    )
                })
                .transpose()?;
            let persisted = match existing_for_receipt {
                Some(existing) => {
                    if !same_unsigned_receipt_and_bbs_binding(&existing, &receipt)? {
                        return Err(ReceiptStoreError::Conflict(format!(
                            "active-defense receipt `{}` already exists with different unsigned content",
                            receipt.id
                        )));
                    }
                    existing
                }
                None => {
                    append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
                    ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
                    receipt
                }
            };
            if let Some(existing_evidence_id) = tx
                .query_row(
                    "SELECT evidence_id FROM chio_security_evidence_index WHERE receipt_id = ?1",
                    params![persisted.id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "active-defense receipt `{}` is already mapped to evidence `{existing_evidence_id}`",
                    persisted.id
                )));
            }
            tx.execute(
                "INSERT INTO chio_security_evidence_index (evidence_id, receipt_id) VALUES (?1, ?2)",
                params![evidence_id.as_str(), persisted.id.as_str()],
            )?;
            tx.commit()?;
            Ok(persisted)
        })
    }

    pub fn load_indexed_security_evidence(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        connection
            .query_row(
                r#"
                SELECT receipt.seq, receipt.raw_json
                FROM chio_security_evidence_index AS evidence
                JOIN chio_tool_receipts AS receipt
                  ON receipt.receipt_id = evidence.receipt_id
                WHERE evidence.evidence_id = ?1
                "#,
                params![evidence_id.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(seq, raw_json)| {
                let receipt = decode_verified_chio_receipt(
                    &raw_json,
                    "indexed active-defense receipt",
                    Some(seq.max(0) as u64),
                )?;
                validate_indexed_security_receipt(evidence_id, &receipt)?;
                Ok(receipt)
            })
            .transpose()
    }

    pub fn ensure_indexed_security_evidence_ready(&self) -> Result<(), ReceiptStoreError> {
        let health = self.receipt_store_health()?;
        if !health.healthy {
            return Err(ReceiptStoreError::Conflict(
                "indexed security evidence store is not healthy".to_string(),
            ));
        }
        let connection = self.connection()?;
        bootstrap::open::validate_indexed_security_evidence_schema(&connection)
    }

    pub fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush()?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    /// Rerun the one-time full verification on the writer connection and
    /// adopt the resulting head. This is the `chio receipt audit --repair`
    /// entry point; it is also safe to call on a healthy store.
    pub fn reseed_verified_head(&self) -> Result<(), ReceiptStoreError> {
        self.database_identity_file.validate()?;
        let (response, result) = mpsc::sync_channel(1);
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::ReseedHead(response))
        {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(receipt_actor_saturated_error()),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(receipt_actor_unavailable_error());
            }
        }
        result
            .recv()
            .map_err(|_| receipt_actor_unavailable_error())?
    }

    /// Install the background checkpoint signer. Idempotent per store (a
    /// second call replaces the signer). Until called, the store appends
    /// without producing checkpoints.
    pub fn enable_background_checkpoints(
        &self,
        signer: BackgroundCheckpointSigner,
    ) -> Result<(), ReceiptStoreError> {
        self.database_identity_file.validate()?;
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::InstallSigner(signer))
        {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => Err(receipt_actor_saturated_error()),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(receipt_actor_unavailable_error()),
        }
    }

    pub fn flush_receipt_writes_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush_with_timeout(timeout)?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    pub fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let status = self.receipt_checkpoint_status(Some(1))?;
        if status.latest_committed_entry_seq > status.latest_checkpointed_entry_seq {
            let connection = self.connection()?;
            let start_seq = status.latest_checkpointed_entry_seq + 1;
            load_claim_tree_canonical_bytes_range(
                &connection,
                start_seq,
                status.latest_committed_entry_seq,
            )?;
        }
        let healthy = status.healthy
            && self
                .receipt_commit_actor
                .writer_counters()
                .last_error
                .is_none();
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) = uncheckpointed_range(
            status.latest_checkpointed_entry_seq,
            status.latest_committed_entry_seq,
        );
        Ok(ReceiptStoreHealthReport {
            healthy,
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq: status.latest_committed_entry_seq,
            latest_checkpoint_seq: status.latest_checkpoint_seq,
            latest_checkpointed_entry_seq: status.latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            checkpoint_error: status.checkpoint_error,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    /// Sample receipt-store health from a READ-ONLY connection.
    ///
    /// The SIEM serve-mode watchdog observes a receipt DB the kernel owns; it
    /// must not create it, switch it to WAL, or spin a writer pool on it,
    /// matching the read-only receipt-polling contract. `open` does all three, so
    /// it cannot be used on a read-only mount and would create an empty DB on a
    /// mistyped path. This opens a single READ_ONLY connection instead: a missing
    /// file reports `NotFound` rather than being created, and a read-only mount
    /// is sampled without any write attempt.
    ///
    /// A read-only observer cannot see the owning writer's in-memory counters, so
    /// `writer` is defaulted; the checkpoint-progress fields the watchdog gauges
    /// consume (committed/checkpointed seqs and the uncheckpointed range) are
    /// computed from the read connection with the same helpers as
    /// `receipt_store_health`.
    pub fn receipt_store_health_read_only(
        path: &Path,
    ) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::CannotOpen) {
                ReceiptStoreError::NotFound(format!(
                    "receipt database {} does not exist",
                    path.display()
                ))
            } else {
                ReceiptStoreError::Sqlite(error)
            }
        })?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        // Catch a checkpoint-chain-integrity failure into a report with the
        // checkpoint_error set rather than propagating Err. The watchdog samples
        // this on a fixed interval; if corruption made this return Err, the
        // sampler would log-and-skip with NO gauge update, so a corrupt store
        // would look silent instead of alarming. Mirror the
        // fail-open shape of `receipt_checkpoint_status` so the watchdog still
        // emits a large-backlog gauge (checkpointed defaults to 0 -> the
        // uncheckpointed range spans the whole committed log) with the
        // checkpoint_error attached.
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
                    uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
                Ok(ReceiptStoreHealthReport {
                    healthy: latest_committed_entry_seq >= latest_checkpointed_entry_seq,
                    writer: ReceiptWriterCounters::default(),
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    uncheckpointed_start_seq,
                    uncheckpointed_end_seq,
                    checkpoint_error: None,
                    db_size_bytes: None,
                })
            }
            Err(error) => {
                let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
                    uncheckpointed_range(0, latest_committed_entry_seq);
                Ok(ReceiptStoreHealthReport {
                    healthy: false,
                    writer: ReceiptWriterCounters::default(),
                    latest_committed_entry_seq,
                    latest_checkpoint_seq: None,
                    latest_checkpointed_entry_seq: 0,
                    uncheckpointed_start_seq,
                    uncheckpointed_end_seq,
                    checkpoint_error: Some(error.to_string()),
                    db_size_bytes: None,
                })
            }
        }
    }

    pub fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_claim_log_entry_seq(&connection)
    }

    pub fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_checkpointed_entry_seq(&connection)
    }

    pub fn next_checkpoint_range(
        &self,
        max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        let connection = self.connection()?;
        next_checkpoint_range_for_connection(&connection, max_batch)
    }

    pub fn receipt_checkpoint_status(
        &self,
        max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let connection = self.connection()?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                if latest_committed_entry_seq > latest_checkpointed_entry_seq {
                    let start_seq = latest_checkpointed_entry_seq + 1;
                    if let Err(error) = ensure_claim_log_range_contiguous(
                        &connection,
                        start_seq,
                        latest_committed_entry_seq,
                        "uncheckpointed range",
                    ) {
                        return Ok(ReceiptCheckpointStatusReport {
                            healthy: false,
                            latest_committed_entry_seq,
                            latest_checkpoint_seq,
                            latest_checkpointed_entry_seq,
                            next_range: None,
                            checkpoint_error: Some(error.to_string()),
                        });
                    }
                }
                let next_range = match max_batch {
                    Some(max_batch) => {
                        next_checkpoint_range_for_connection(&connection, max_batch)?
                    }
                    None => None,
                };
                Ok(ReceiptCheckpointStatusReport {
                    healthy: true,
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    next_range,
                    checkpoint_error: None,
                })
            }
            Err(error) => Ok(ReceiptCheckpointStatusReport {
                healthy: false,
                latest_committed_entry_seq,
                latest_checkpoint_seq: None,
                latest_checkpointed_entry_seq: 0,
                next_range: None,
                checkpoint_error: Some(error.to_string()),
            }),
        }
    }

    pub fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        let keypair = keypair.clone();
        self.writer_handle().run_write(move |connection| {
            validate_claim_receipt_log_entries(connection)?;
            create_next_receipt_checkpoint_atomic(connection, max_batch, &keypair)
        })
    }

    fn flush_report(
        &self,
        wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        let head = self.writer_head_snapshot();
        let connection = self.connection()?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        // The writer head snapshot is only refreshed by this handle's own
        // appends/writes. When another store instance or the operator CLI
        // extends the checkpoint chain and this handle has had no intervening
        // local write, the head atomics are stale and would overstate the
        // uncheckpointed range. Read the persisted checkpoint head from the DB
        // (read-only reader-pool query, not a writer-head mutation) and take
        // the higher of the two so the report reflects the current chain.
        // Only trust the persisted latest checkpoint if its signed body
        // VERIFIES: `parse_persisted_checkpoint_row` checks
        // column/body agreement AND the signature, so a tampered or out-of-band
        // row with an inflated `batch_end_seq` cannot make the flush report a
        // false `checkpointed_entry_seq` and hide the uncheckpointed range. On a
        // verification failure fall back to ONLY the actor's verified head (via
        // the `.max` below). Reader-pool READ, no write; single latest-row
        // body verification, not a full chain verify.
        //
        // Chain-connectivity guard: a single-row parse
        // does NOT catch a latest checkpoint that individually verifies yet is
        // DISCONNECTED from the chain (skipped `checkpoint_seq` or wrong
        // predecessor), which a full `verify_checkpoint_chain_integrity`
        // catches. Additionally require
        // the latest checkpoint to link to its immediate predecessor before
        // trusting its `batch_end_seq`; a disconnected latest is dropped (fall
        // back to the actor's verified head). This is a bounded O(1) predecessor
        // read on the operator/health surface, NOT a full O(N) chain walk on the
        // per-append hot path.
        //
        // Claim-log content guard: a separate process
        // advancing `kernel_checkpoints` on a shared DB can persist a latest row
        // that parses (columns match its signed body) AND links to its predecessor
        // yet whose `merkle_root`/`tree_size`/`batch_end_seq` describe a batch this
        // database's `claim_receipt_log_entries` never actually contained (an
        // imported/foreign checkpoint). A full `verify_checkpoint_chain_integrity`
        // rebuilds the checkpoint Merkle range from the local claim log; without
        // that content check here an
        // inflated `batch_end_seq` would make this report advertise a false
        // `checkpointed_entry_seq` and hide the uncheckpointed range. Rebuild the
        // latest checkpoint's Merkle range from the LOCAL claim log and drop it on
        // mismatch (fall back to the actor's verified head). Bounded O(b) over the
        // single latest checkpoint's own batch on the operator/health surface, NOT
        // a full O(N) chain walk on the per-append hot path.
        let verified_persisted = load_latest_persisted_checkpoint_row(&connection)?
            .and_then(|row| parse_persisted_checkpoint_row(row).ok())
            .filter(|checkpoint| {
                latest_checkpoint_is_chain_connected(&connection, checkpoint).is_ok()
                    && validate_checkpoint_against_claim_log(&connection, checkpoint).is_ok()
            });
        let persisted_checkpoint_seq = verified_persisted
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.checkpoint_seq);
        let persisted_checkpointed_entry_seq = verified_persisted
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        let checkpoint_seq = head.checkpoint_seq.max(persisted_checkpoint_seq);
        let latest_checkpointed_entry_seq = head
            .checkpointed_entry_seq
            .max(persisted_checkpointed_entry_seq);
        let latest_checkpoint_seq = (checkpoint_seq > 0).then_some(checkpoint_seq);
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
            uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
        Ok(ReceiptFlushReport {
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq,
            latest_checkpoint_seq,
            latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            wal_checkpoint,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    fn validate_claim_receipt_log_projection_current(&self) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        validate_claim_receipt_log_entries(&connection)
    }

    fn wal_checkpoint_passive(&self) -> Result<ReceiptWalCheckpointReport, ReceiptStoreError> {
        let connection = self.connection()?;
        let (busy, log_frames, checkpointed_frames) =
            connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
        Ok(ReceiptWalCheckpointReport {
            busy: sqlite_u64(busy, "wal checkpoint busy")?,
            log_frames: wal_checkpoint_frame_count(log_frames, "wal checkpoint log frames")?,
            checkpointed_frames: wal_checkpoint_frame_count(
                checkpointed_frames,
                "wal checkpointed frames",
            )?,
        })
    }
}

fn validate_indexed_security_receipt(
    evidence_id: &OpaqueReceiptRef,
    receipt: &ChioReceipt,
) -> Result<(), ReceiptStoreError> {
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "indexed active-defense receipt is missing security metadata".to_string(),
        )
    })?;
    let claimed_evidence_id = metadata
        .get("active_defense_evidence_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "indexed active-defense receipt is missing its logical evidence ID".to_string(),
            )
        })?;
    let body: ActiveDefenseReceiptBody = serde_json::from_value(
        metadata
            .get("active_defense_body")
            .cloned()
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "indexed active-defense receipt is missing its closed body".to_string(),
                )
            })?,
    )
    .map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense receipt body is invalid: {error}"
        ))
    })?;
    body.validate().map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense receipt body is invalid: {error}"
        ))
    })?;
    let derived_evidence_id = body.evidence_id().map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense evidence ID derivation failed: {error}"
        ))
    })?;
    let body_digest = body.body_digest().map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense body digest failed: {error}"
        ))
    })?;
    if claimed_evidence_id != evidence_id.as_str()
        || &derived_evidence_id != evidence_id
        || receipt.tool_origin != chio_core::receipt::kinds::ToolOrigin::ChioInternal
        || receipt.tool_server != "chio.kernel"
        || receipt.tool_name != body.kind().as_str()
        || receipt.tenant_id.as_deref() != Some(body.header().tenant_id.as_str())
        || receipt.content_hash != hex::encode(body_digest.as_bytes())
    {
        return Err(ReceiptStoreError::Conflict(
            "indexed active-defense receipt binding is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn same_unsigned_receipt_and_bbs_binding(
    left: &ChioReceipt,
    right: &ChioReceipt,
) -> Result<bool, ReceiptStoreError> {
    let left_body = canonical_json_bytes(&left.body())
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let right_body = canonical_json_bytes(&right.body())
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let left_bbs = canonical_json_bytes(&left.bbs_signature)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let right_bbs = canonical_json_bytes(&right.bbs_signature)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    Ok(left_body == right_body && left_bbs == right_bbs)
}

/// `PRAGMA wal_checkpoint` reports -1 for the log/checkpointed frame columns
/// when there is nothing to checkpoint (an already-empty WAL). Under
/// concurrent `flush_receipt_writes()` callers this is routine: one caller's
/// PASSIVE checkpoint truncates the WAL, and a second caller racing right
/// behind it observes the now-empty WAL and gets -1/-1 from SQLite even
/// though `busy` is 0 (success). That is success-with-nothing-to-do, not an
/// error, so it is normalized to 0 rather than rejected by `sqlite_u64`.
fn wal_checkpoint_frame_count(value: i64, field: &str) -> Result<u64, ReceiptStoreError> {
    if value == -1 {
        return Ok(0);
    }
    sqlite_u64(value, field)
}

fn uncheckpointed_range(checkpointed: u64, committed: u64) -> (Option<u64>, Option<u64>) {
    if committed > checkpointed {
        (Some(checkpointed + 1), Some(committed))
    } else {
        (None, None)
    }
}

fn latest_claim_log_entry_seq(connection: &Connection) -> Result<u64, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT COALESCE(MAX(entry_seq), 0) FROM claim_receipt_log_entries",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(ReceiptStoreError::from)
        .and_then(|value| sqlite_u64(value, "latest claim receipt log entry_seq"))
}

fn latest_checkpointed_entry_seq(connection: &Connection) -> Result<u64, ReceiptStoreError> {
    verify_checkpoint_chain_integrity(connection)
        .map(|latest| latest.map_or(0, |checkpoint| checkpoint.body.batch_end_seq))
}

fn next_checkpoint_range_for_connection(
    connection: &Connection,
    max_batch: u64,
) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
    if max_batch == 0 {
        return Err(ReceiptStoreError::Conflict(
            "checkpoint max_batch must be greater than zero".to_string(),
        ));
    }
    let latest_committed = latest_claim_log_entry_seq(connection)?;
    let latest_checkpointed = latest_checkpointed_entry_seq(connection)?;
    if latest_committed <= latest_checkpointed {
        return Ok(None);
    }
    let start_seq = latest_checkpointed + 1;
    let end_seq = latest_committed.min(start_seq.saturating_add(max_batch - 1));
    ensure_claim_log_range_contiguous(connection, start_seq, end_seq, "checkpoint range")?;
    Ok(Some(ReceiptCheckpointRange { start_seq, end_seq }))
}

fn ensure_claim_log_range_contiguous(
    connection: &Connection,
    start_seq: u64,
    end_seq: u64,
    context: &str,
) -> Result<(), ReceiptStoreError> {
    if end_seq < start_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log {context} end {end_seq} is before start {start_seq}"
        )));
    }
    let (count, min_seq, max_seq) = connection.query_row(
        r#"
        SELECT COUNT(*), MIN(entry_seq), MAX(entry_seq)
        FROM claim_receipt_log_entries
        WHERE entry_seq >= ?1 AND entry_seq <= ?2
        "#,
        params![
            sqlite_i64(start_seq, "claim log range start_seq")?,
            sqlite_i64(end_seq, "claim log range end_seq")?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        },
    )?;
    let expected = end_seq - start_seq + 1;
    let count = sqlite_u64(count, "claim receipt log range count")?;
    let min_seq = min_seq
        .map(|value| sqlite_u64(value, "claim receipt log range min_seq"))
        .transpose()?;
    let max_seq = max_seq
        .map(|value| sqlite_u64(value, "claim receipt log range max_seq"))
        .transpose()?;
    if count != expected || min_seq != Some(start_seq) || max_seq != Some(end_seq) {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log has a gap in {context} {start_seq}..={end_seq}"
        )));
    }
    Ok(())
}

fn claim_log_entry_seq_for_source_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_kind: &str,
    source_seq: u64,
) -> Result<u64, ReceiptStoreError> {
    let source_seq_i64 = sqlite_i64(source_seq, "claim receipt source_seq")?;
    let (entry_seq, log_receipt_id, log_raw_json, source_receipt_id, source_raw_json) =
        match receipt_kind {
            "tool_receipt" => tx.query_row(
                r#"
                SELECT l.entry_seq, l.receipt_id, l.raw_json, r.receipt_id, r.raw_json
                FROM claim_receipt_log_entries l
                JOIN chio_tool_receipts r ON r.seq = l.source_seq
                WHERE l.receipt_kind = ?1 AND l.source_seq = ?2
                "#,
                params![receipt_kind, source_seq_i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            ),
            "child_receipt" => tx.query_row(
                r#"
                SELECT l.entry_seq, l.receipt_id, l.raw_json, r.receipt_id, r.raw_json
                FROM claim_receipt_log_entries l
                JOIN chio_child_receipts r ON r.seq = l.source_seq
                WHERE l.receipt_kind = ?1 AND l.source_seq = ?2
                "#,
                params![receipt_kind, source_seq_i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            ),
            other => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "unsupported claim receipt log kind `{other}`"
                )));
            }
        }
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "claim receipt log entry missing for {receipt_kind} source seq {source_seq}"
            ))
        })?;
    if log_receipt_id != source_receipt_id || log_raw_json != source_raw_json {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log entry for {receipt_kind} source seq {source_seq} diverges from source row"
        )));
    }
    sqlite_positive_u64(entry_seq, "claim receipt log entry_seq")
}

fn append_chio_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt: &ChioReceipt,
    raw_json: &str,
) -> Result<u64, ReceiptStoreError> {
    let attribution = extract_receipt_attribution(receipt);
    let mut subject_key = attribution.subject_key;
    let mut issuer_key = attribution.issuer_key;
    if subject_key.is_none() || issuer_key.is_none() {
        if let Some((lineage_subject_key, lineage_issuer_key)) = tx
            .query_row(
                "SELECT subject_key, issuer_key FROM capability_lineage WHERE capability_id = ?1",
                params![receipt.capability_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?
        {
            if subject_key.is_none() {
                subject_key = lineage_subject_key;
            }
            if issuer_key.is_none() {
                issuer_key = lineage_issuer_key;
            }
        }
    }
    let source_seq = tx
        .query_row(
            r#"
        INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, tool_server, tool_name, decision_kind, policy_hash, content_hash, tenant_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO NOTHING RETURNING seq
        "#,
            params![
                receipt.id.as_str(),
                sqlite_i64(receipt.timestamp, "receipt timestamp")?,
                receipt.capability_id.as_str(),
                subject_key,
                issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
                receipt_decision_kind(receipt),
                receipt.policy_hash.as_str(),
                receipt.content_hash.as_str(),
                receipt.tenant_id.as_deref(),
                raw_json,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(source_seq) = source_seq else {
        let (existing_source_seq, existing_raw_json) = tx.query_row(
            "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt.id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        let existing_source_seq =
            sqlite_positive_u64(existing_source_seq, "tool receipt source_seq")?;
        if existing_raw_json != raw_json {
            return Err(ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` already exists with different content",
                receipt.id
            )));
        }
        decode_verified_chio_receipt(
            &existing_raw_json,
            "persisted duplicate tool receipt",
            Some(existing_source_seq),
        )?;
        return claim_log_entry_seq_for_source_tx(tx, "tool_receipt", existing_source_seq);
    };
    let source_seq = sqlite_positive_u64(source_seq, "tool receipt source_seq")?;
    claim_log_entry_seq_for_source_tx(tx, "tool_receipt", source_seq)
}

fn consume_authorization_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    consumption: &AuthorizationReceiptConsumption,
) -> Result<(), ReceiptStoreError> {
    if consumption.authorization_receipt_id.trim().is_empty()
        || consumption.consumer_receipt_id.trim().is_empty()
        || consumption.request_id.trim().is_empty()
        || consumption.session_id.trim().is_empty()
        || consumption.tool_call_id.trim().is_empty()
        || consumption.parameter_hash.trim().is_empty()
    {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt consumption requires non-empty binding fields".to_string(),
        ));
    }
    // Tenant id may be `None` for non-enterprise / single-tenant deployments,
    // but if it is `Some(_)` it must not be an empty / whitespace-only string.
    if matches!(&consumption.tenant_id, Some(tenant) if tenant.trim().is_empty()) {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt consumption tenant id must not be empty when present"
                .to_string(),
        ));
    }
    let consumed_at = sqlite_i64(
        consumption.consumed_at_unix_ms,
        "authorization receipt consumed_at_unix_ms",
    )?;
    let authorization_tenant = tx
        .query_row(
            "SELECT tenant_id FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![consumption.authorization_receipt_id.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::NotFound(format!(
                "authorization receipt {} was not found",
                consumption.authorization_receipt_id
            ))
        })?;
    if authorization_tenant.as_deref() != consumption.tenant_id.as_deref() {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt tenant id does not match consumption tenant".to_string(),
        ));
    }
    match tx.execute(
        r#"
        INSERT INTO chio_authorization_receipt_consumptions (
            authorization_receipt_id,
            consumer_receipt_id,
            request_id,
            session_id,
            tool_call_id,
            tenant_id,
            parameter_hash,
            consumed_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            consumption.authorization_receipt_id.as_str(),
            consumption.consumer_receipt_id.as_str(),
            consumption.request_id.as_str(),
            consumption.session_id.as_str(),
            consumption.tool_call_id.as_str(),
            consumption.tenant_id.as_deref(),
            consumption.parameter_hash.as_str(),
            consumed_at,
        ],
    ) {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            ) =>
        {
            Err(ReceiptStoreError::Conflict(
                "authorization receipt already consumed".to_string(),
            ))
        }
        Err(error) => Err(ReceiptStoreError::Sqlite(error)),
    }
}

fn decode_canonical_chio_receipt(
    canonical: &CanonicalBytes,
) -> Result<ChioReceipt, ReceiptStoreError> {
    let receipt: ChioReceipt =
        serde_json::from_slice(canonical.as_bytes()).map_err(ReceiptStoreError::from)?;
    let expected = canonical_json_bytes(&receipt)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    if expected.as_slice() != canonical.as_bytes() {
        return Err(ReceiptStoreError::Canonical(
            "canonical receipt bytes do not match ChioReceipt serialization".to_string(),
        ));
    }
    Ok(receipt)
}

fn canonical_receipt_json(canonical: &CanonicalBytes) -> Result<&str, ReceiptStoreError> {
    std::str::from_utf8(canonical.as_bytes()).map_err(|error| {
        ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
    })
}
