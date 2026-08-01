const SETTLEMENT_OBSERVER_OUTBOX_RECEIPT_ID_MAX_BYTES: usize = 512;
const SETTLEMENT_OBSERVER_OUTBOX_CLAIM_TOKEN_MAX_BYTES: usize = 512;
const SETTLEMENT_OBSERVER_OUTBOX_STAGED_STATUS_MAX_BYTES: usize = 65_536;
const SETTLEMENT_OBSERVER_OUTBOX_LAST_ERROR_MAX_BYTES: usize = 2_048;

fn validate_settlement_observer_outbox_text(
    value: &str,
    field: &str,
    max_bytes: usize,
) -> Result<(), ReceiptStoreError> {
    if value.trim().is_empty() {
        return Err(ReceiptStoreError::Conflict(format!(
            "settlement-observer outbox {field} must not be empty"
        )));
    }
    if value.len() > max_bytes {
        return Err(ReceiptStoreError::Conflict(format!(
            "settlement-observer outbox {field} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn truncate_settlement_observer_outbox_error(value: &str) -> String {
    if value.len() <= SETTLEMENT_OBSERVER_OUTBOX_LAST_ERROR_MAX_BYTES {
        return value.to_string();
    }
    let mut end = SETTLEMENT_OBSERVER_OUTBOX_LAST_ERROR_MAX_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Writer-actor checkpoint head consumed by production flush reporting.
pub(crate) struct WriterCheckpointSnapshot {
    pub(crate) checkpoint_seq: u64,
    pub(crate) checkpointed_entry_seq: u64,
}

/// Complete writer head exposed only to in-crate verification.
#[cfg(test)]
pub(crate) struct WriterHeadSnapshot {
    pub(crate) checkpoint_seq: u64,
    pub(crate) checkpointed_entry_seq: u64,
    pub(crate) claim_log_count: u64,
    pub(crate) claim_log_max_seq: u64,
}

/// Seed the verified head by running the existing FULL verification exactly
/// once (the startup path for the O(N) check; also the audit-repair path).
fn seed_verified_head(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    validate_claim_receipt_log_entries(connection)?;
    let (latest_checkpoint, chain_frontier) =
        verify_checkpoint_chain_integrity_with_frontier(connection)?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        chain_frontier: Some(chain_frontier),
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
        chain_frontier: None,
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
    let retention_watermark = trusted_retention_watermark(connection)?;
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
        if checkpoint.body.batch_end_seq > retention_watermark {
            validate_checkpoint_against_claim_log(connection, &checkpoint)?;
        }
        // Projection validation before adoption: the
        // catch-up path verified signature + predecessor + claim-log range but
        // not the transparency projection rows that full
        // `verify_checkpoint_chain_integrity` rejects. Adopting a checkpoint with
        // missing/divergent projection rows would advance `head.latest_checkpoint`
        // and let subsequent appends build on an audit-invalid chain. Validate ONLY
        // this adopted checkpoint's projection rows (O(b) for its batch, not full
        // history), fail closed on any divergence.
        validate_checkpoint_projection_rows(connection, &row, &checkpoint)?;
        head.chain_frontier = Some(advance_verified_checkpoint_chain_frontier(
            connection,
            head.chain_frontier.as_ref(),
            head.latest_checkpoint.as_ref(),
            &checkpoint,
        )?);
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
    pool: &Pool<ReceiptConnectionManager>,
    head: &mut VerifiedHead,
    incremental_verification: bool,
    requests: &[ReceiptCommitRequest],
) -> Result<Vec<Result<u64, ReceiptStoreError>>, ReceiptStoreError> {
    let mut connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    ensure_checkpoint_transparency_guards(&connection)?;
    if incremental_verification {
        // O(1) predecessor check (+ bounded catch-up), not a chain rebuild.
        verify_head_against_latest_checkpoint(&connection, head)?;
    } else {
        validate_claim_receipt_log_entries(&connection)?;
    }
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if !incremental_verification {
        verify_latest_checkpoint_integrity(&tx)?;
    }
    // Baseline inside the IMMEDIATE tx: rows another store instance committed
    // since our last look are adopted as pre-existing, so the cross-check
    // below measures exactly what THIS batch inserted.
    let (pre_delta, baseline_max) =
        claim_log_delta_count_and_max_seq(&tx, head.claim_log_max_seq)?;
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
        validate_adopted_claim_log_delta(&tx, head.claim_log_max_seq, baseline_max)?;
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
        tx.execute_batch("SAVEPOINT chio_append_record")?;
        match append_single_receipt_record(&tx, request) {
            Ok(seq) => {
                tx.execute_batch("RELEASE chio_append_record")?;
                results.push(Ok(seq));
            }
            Err(error) => {
                // Fail THIS record closed and undo only its work, then keep going
                // for the others. A savepoint that will not unwind is a
                // transaction-integrity fault, so fail the whole batch closed in
                // that (unexpected) case.
                tx.execute_batch(
                    "ROLLBACK TO chio_append_record; RELEASE chio_append_record",
                )?;
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
    #[cfg(feature = "chaos-test-hooks")]
    chaos_test_hooks::pause_after_receipt_write_before_commit(inserted > 0)?;
    // O(b) projection cross-check over the delta only: the claim-log
    // projection triggers (bootstrap/open.rs:676 tool, :711 child) must have
    // advanced the projection by exactly the rows this batch inserted.
    let (delta_count, post_max) = claim_log_delta_count_and_max_seq(&tx, baseline_max)?;
    if delta_count != inserted || post_max < baseline_max {
        return Err(ReceiptStoreError::Conflict(
            "claim receipt log projection drift on append; run `chio receipt audit`".to_string(),
        ));
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
        validate_adopted_claim_log_delta(&tx, baseline_max, post_max)?;
    }
    tx.commit()?;
    head.claim_log_count = head
        .claim_log_count
        .saturating_add(pre_delta)
        .saturating_add(delta_count);
    head.claim_log_max_seq = post_max.max(baseline_max);
    Ok(results)
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
        ReceiptStoreError::RetentionArchiveIncomplete {
            table,
            live,
            archived,
        } => ReceiptStoreError::RetentionArchiveIncomplete {
            table,
            live: *live,
            archived: *archived,
        },
        ReceiptStoreError::RetentionWatermarkRegression { attempted, current } => {
            ReceiptStoreError::RetentionWatermarkRegression {
                attempted: *attempted,
                current: *current,
            }
        }
        ReceiptStoreError::ArchivedRangeProjection { watermark } => {
            ReceiptStoreError::ArchivedRangeProjection {
                watermark: *watermark,
            }
        }
        ReceiptStoreError::RetentionTenantScopeUnsupported => {
            ReceiptStoreError::RetentionTenantScopeUnsupported
        }
        ReceiptStoreError::WriterDead {
            restarts,
            last_error,
        } => ReceiptStoreError::WriterDead {
            restarts: *restarts,
            last_error: last_error.clone(),
        },
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
/// itself. The batch's moved inflight leases drop during unwind before this
/// function runs, so this path updates result counters and sends errors without
/// a second aggregate inflight decrement.
fn fan_out_batch_panic_error(
    health: &ReceiptCommitWriterHealth,
    request_responses: Vec<mpsc::SyncSender<Result<u64, ReceiptStoreError>>>,
    error: ReceiptStoreError,
) -> ReceiptStoreError {
    let batch_len = request_responses.len() as u64;
    health.failed_total.fetch_add(batch_len, Ordering::SeqCst);
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
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::Mutex;

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
    /// NON-panic checkpoint-build failure) for a signer using either dedicated
    /// failure marker, proving build failures are surfaced and checkpoint debt
    /// never regresses across signer replacement. Both use values distinct from
    /// `PANIC_DURING_CHECKPOINT_BUILD` so the two process-global flags cannot
    /// interfere across the crate's parallel tests.
    pub(crate) static FAIL_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

    static FAIL_CHECKPOINT_BUILD_TEST_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) const FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 7;
    pub(crate) const FAIL_CHECKPOINT_BUILD_SECONDARY_MARKER_MAX_BATCH: u64 = 6;

    pub(crate) fn fail_checkpoint_build(max_batch: u64) -> bool {
        (max_batch == FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH
            || max_batch == FAIL_CHECKPOINT_BUILD_SECONDARY_MARKER_MAX_BATCH)
            && FAIL_CHECKPOINT_BUILD.load(Ordering::SeqCst)
    }

    pub(crate) fn checkpoint_build_failure_test_lock() -> std::sync::MutexGuard<'static, ()> {
        match FAIL_CHECKPOINT_BUILD_TEST_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Hold a checkpoint build after the signed body exists but before its
    /// transaction opens. The dedicated marker isolates this process-global
    /// hook from unrelated checkpoint tests. It lets the Flush barrier test
    /// sample writer accounting while checkpoint work is still in progress.
    const BLOCK_STATE_DISARMED: u8 = 0;
    const BLOCK_STATE_ARMED: u8 = 1;
    const BLOCK_STATE_ENTERED: u8 = 2;
    const BLOCK_STATE_RELEASED: u8 = 3;
    static CHECKPOINT_BUILD_BLOCK_STATE: AtomicU8 = AtomicU8::new(BLOCK_STATE_DISARMED);
    static CHECKPOINT_BUILD_BLOCK_TEST_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) const BLOCK_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 11;

    pub(crate) struct CheckpointBuildBlockGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CheckpointBuildBlockGuard {
        pub(crate) fn arm() -> Self {
            let lock = match CHECKPOINT_BUILD_BLOCK_TEST_LOCK.lock() {
                Ok(lock) => lock,
                Err(poisoned) => poisoned.into_inner(),
            };
            CHECKPOINT_BUILD_BLOCK_STATE.store(BLOCK_STATE_ARMED, Ordering::SeqCst);
            Self { _lock: lock }
        }

        pub(crate) fn release(&self) {
            release_block_state(&CHECKPOINT_BUILD_BLOCK_STATE);
        }
    }

    impl Drop for CheckpointBuildBlockGuard {
        fn drop(&mut self) {
            self.release();
        }
    }

    pub(crate) fn checkpoint_build_block_entered() -> bool {
        matches!(
            CHECKPOINT_BUILD_BLOCK_STATE.load(Ordering::SeqCst),
            BLOCK_STATE_ENTERED | BLOCK_STATE_RELEASED
        )
    }

    pub(crate) fn block_during_checkpoint_build(max_batch: u64) {
        if max_batch != BLOCK_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH {
            return;
        }
        if CHECKPOINT_BUILD_BLOCK_STATE
            .compare_exchange(
                BLOCK_STATE_ARMED,
                BLOCK_STATE_ENTERED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return;
        }
        while CHECKPOINT_BUILD_BLOCK_STATE.load(Ordering::SeqCst) != BLOCK_STATE_RELEASED {
            std::thread::yield_now();
        }
        CHECKPOINT_BUILD_BLOCK_STATE.store(BLOCK_STATE_DISARMED, Ordering::SeqCst);
    }

    fn release_block_state(state: &AtomicU8) {
        loop {
            match state.load(Ordering::SeqCst) {
                BLOCK_STATE_DISARMED => return,
                BLOCK_STATE_ARMED => {
                    if state
                        .compare_exchange(
                            BLOCK_STATE_ARMED,
                            BLOCK_STATE_DISARMED,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        return;
                    }
                }
                BLOCK_STATE_ENTERED => {
                    if state
                        .compare_exchange(
                            BLOCK_STATE_ENTERED,
                            BLOCK_STATE_RELEASED,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        while state.load(Ordering::SeqCst) != BLOCK_STATE_DISARMED {
                            std::thread::yield_now();
                        }
                        return;
                    }
                }
                BLOCK_STATE_RELEASED => {
                    while state.load(Ordering::SeqCst) != BLOCK_STATE_DISARMED {
                        std::thread::yield_now();
                    }
                    return;
                }
                _ => return,
            }
        }
    }

    /// Hold a full ReseedHead verification after it owns the writer connection.
    /// The source-row marker prevents the process-global flag from affecting
    /// unrelated reseed tests running in parallel.
    pub(crate) static BLOCK_DURING_RESEED: AtomicBool = AtomicBool::new(false);
    pub(crate) static BLOCK_DURING_RESEED_ENTERED: AtomicBool = AtomicBool::new(false);
    pub(crate) static RELEASE_BLOCKED_RESEED: AtomicBool = AtomicBool::new(false);
    pub(crate) const BLOCK_DURING_RESEED_MARKER_CONTENT_HASH: &str =
        "content-test-hook-block-during-reseed";

    pub(crate) struct ReseedBlockGuard;

    impl ReseedBlockGuard {
        pub(crate) fn arm() -> Self {
            BLOCK_DURING_RESEED_ENTERED.store(false, Ordering::SeqCst);
            RELEASE_BLOCKED_RESEED.store(false, Ordering::SeqCst);
            BLOCK_DURING_RESEED.store(true, Ordering::SeqCst);
            Self
        }

        pub(crate) fn release(&self) {
            RELEASE_BLOCKED_RESEED.store(true, Ordering::SeqCst);
            BLOCK_DURING_RESEED.store(false, Ordering::SeqCst);
        }
    }

    impl Drop for ReseedBlockGuard {
        fn drop(&mut self) {
            self.release();
            BLOCK_DURING_RESEED_ENTERED.store(false, Ordering::SeqCst);
        }
    }

    pub(crate) fn block_during_reseed(connection: &rusqlite::Connection) {
        if !BLOCK_DURING_RESEED.load(Ordering::SeqCst) {
            return;
        }
        let marker_present = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM chio_tool_receipts WHERE content_hash = ?1)",
                rusqlite::params![BLOCK_DURING_RESEED_MARKER_CONTENT_HASH],
                |row| row.get::<_, i64>(0),
            )
            .map(|present| present != 0)
            .unwrap_or(false);
        if !marker_present {
            return;
        }
        BLOCK_DURING_RESEED_ENTERED.store(true, Ordering::SeqCst);
        while !RELEASE_BLOCKED_RESEED.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
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

include!("part_02_store_impl.inc");
include!("part_02_security_binding.inc");

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

fn enqueue_settlement_observer_outbox_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt: &ChioReceipt,
) -> Result<(), ReceiptStoreError> {
    validate_settlement_observer_outbox_text(
        &receipt.id,
        "receipt id",
        SETTLEMENT_OBSERVER_OUTBOX_RECEIPT_ID_MAX_BYTES,
    )?;
    tx.execute(
        r#"
        INSERT INTO chio_settlement_observer_outbox (
            receipt_id,
            finalized_at,
            state,
            claim_token,
            claim_deadline_unix_ms,
            version,
            last_error
        ) VALUES (?1, ?2, 'pending', NULL, NULL, 0, NULL)
        ON CONFLICT(receipt_id) DO NOTHING
        "#,
        params![
            receipt.id.as_str(),
            sqlite_i64(receipt.timestamp, "settlement-observer finalized_at")?,
        ],
    )?;
    Ok(())
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
