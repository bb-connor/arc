fn receipt_commit_actor_loop(
    pool: Pool<ReceiptConnectionManager>,
    receiver: &mpsc::Receiver<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
    incremental_verification: bool,
) {
    let mut head_state = match pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
        .and_then(|connection| {
            if incremental_verification {
                seed_verified_head(&connection)
            } else {
                seed_head_snapshot(&connection)
            }
        }) {
        Ok(head) => {
            health.store_head_snapshot(&head);
            // Seeding is authoritative: clear any poison a prior thread run (a
            // panic-then-restart of the supervised writer) may have published.
            health.set_head_poisoned(false);
            WriterHeadState::Verified(Box::new(head))
        }
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
            health.set_head_poisoned(true);
            WriterHeadState::Poisoned(error.to_string())
        }
    };

    let mut pending_flush_error: Option<ReceiptStoreError> = None;
    let mut checkpoint_signer: Option<BackgroundCheckpointSigner> = None;
    while let Ok(command) = receiver.recv() {
        // The command has left the channel; free its slot for the saturation
        // gate. Every command exits the channel through this recv or the batch
        // drain below, so both decrement exactly once per command.
        health.note_channel_dequeue();
        match command {
            ReceiptCommitCommand::Append { request, inflight } => {
                let mut requests = vec![*request];
                let mut inflight_leases = vec![inflight];
                let mut flushes = Vec::new();
                let mut deferred: Option<ReceiptCommitCommand> = None;
                while requests.len() < RECEIPT_GROUP_COMMIT_MAX_BATCH {
                    let next = receiver.recv_timeout(RECEIPT_GROUP_COMMIT_FLUSH_DELAY);
                    if next.is_ok() {
                        health.note_channel_dequeue();
                    }
                    match next {
                        Ok(ReceiptCommitCommand::Append { request, inflight }) => {
                            requests.push(*request);
                            inflight_leases.push(inflight);
                        }
                        Ok(ReceiptCommitCommand::Flush { response, inflight }) => {
                            flushes.push((response, inflight, false));
                            break;
                        }
                        Ok(ReceiptCommitCommand::ShutdownFlush { response, inflight }) => {
                            flushes.push((response, inflight, true));
                            break;
                        }
                        Ok(other) => {
                            // Non-append commands (Write, InstallSigner,
                            // ReseedHead) execute strictly after the batch
                            // they interrupted commits.
                            deferred = Some(other);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                // Panic isolation: `commit_receipt_batch` runs on the single
                // writer thread. A
                // panic anywhere inside it (the append transaction, the
                // lineage fold) must fail THIS batch, not kill the thread.
                // Clone the response channels before handing `requests` /
                // `flushes` to the panicking call: if it unwinds, those
                // values are dropped mid-function and the only way left to
                // answer every caller is through these pre-cloned senders.
                let request_responses: Vec<_> = requests
                    .iter()
                    .map(|request| request.response.clone())
                    .collect();
                // An active signer can make the post-commit checkpoint catch-up
                // synchronously occupy the sole writer after every append
                // response has been delivered. Reserve actor activity BEFORE the
                // batch releases its command leases, so there is no health window
                // with `inflight == 0` while a stalled checkpoint build still owns
                // the writer. This lease is actor work, not another accepted
                // receipt, and is released after the catch-up attempt.
                let checkpoint_activity = if checkpoint_signer
                    .as_ref()
                    .is_some_and(|signer| signer.max_batch > 0)
                {
                    Some(WriterInflightLease::acquire(&health).0)
                } else {
                    None
                };
                // The co-drained Flush waiters are NOT passed into
                // `commit_receipt_batch`; they are released below, AFTER the
                // checkpoint build, so a flush is a genuine checkpoint
                // barrier. Keeping them in the loop lets the
                // success and panic paths fan them out at one point, and
                // because they are not moved into the panicking call they
                // survive an unwind untouched.
                pending_flush_error =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        commit_receipt_batch(
                            &pool,
                            &mut head_state,
                            incremental_verification,
                            requests,
                            inflight_leases,
                            &health,
                        )
                    })) {
                        Ok(flush_error) => flush_error,
                        Err(payload) => {
                            // A panic inside the append or lineage commit is at
                            // least as serious as the store-wide append faults
                            // `commit_receipt_batch` already poisons on: the
                            // batch's durable position can no longer be trusted.
                            // Poison the head so the pre-dispatch gate fails closed
                            // rather than admitting more tools whose receipts may
                            // not persist, until an operator reseeds.
                            let panic_error = receipt_writer_job_panic_error(&payload);
                            health.set_head_poisoned(true);
                            head_state = WriterHeadState::Poisoned(panic_error.to_string());
                            Some(fan_out_batch_panic_error(
                                &health,
                                request_responses,
                                panic_error,
                            ))
                        }
                    };
                // Checkpoint construction runs AFTER commit_receipt_batch has
                // already sent every APPEND durability response, so ADR-0013
                // append latency is not extended by checkpoint building; but it
                // runs BEFORE the co-drained Flush waiters are released, so a
                // flush cannot return until the owed checkpoints for the drained
                // appends are built (the flush-as-checkpoint barrier). A
                // build failure is recorded via `last_error` and does not poison
                // the head, and is surfaced to the co-drained Flush waiters of
                // THIS batch via `flush_barrier_error`. It is deliberately NOT
                // written back into `pending_flush_error`: that keeps the build
                // error scoped to this batch's barrier and preserves the
                // established contract of a later ordinary standalone flush,
                // which reflects append durability. The final shutdown flush is
                // different: it retries any recorded owed checkpoint work and
                // fails close if the retry still fails.
                let mut flush_barrier_error = pending_flush_error
                    .as_ref()
                    .map(receipt_store_error_snapshot);
                if pending_flush_error.is_none() {
                    if let WriterHeadState::Verified(head) = &mut head_state {
                        if let Some(error) = build_due_checkpoints_and_record(
                            &pool,
                            head,
                            &checkpoint_signer,
                            &health,
                        ) {
                            flush_barrier_error = Some(error);
                        }
                    }
                }
                drop(checkpoint_activity);
                // Release the co-drained Flush waiters now that owed checkpoints
                // are built (the checkpoint barrier). An append error or a
                // checkpoint-build failure reaches them as an Err; otherwise Ok.
                for (response, inflight, retry_owed_checkpoints) in flushes {
                    let result = match &flush_barrier_error {
                        Some(error) => Err(receipt_store_error_snapshot(error)),
                        None if retry_owed_checkpoints => retry_owed_checkpoints_for_shutdown(
                            &pool,
                            &mut head_state,
                            &checkpoint_signer,
                            &health,
                        ),
                        None => Ok(()),
                    };
                    if result.is_ok() {
                        health.note_maintenance_success();
                    }
                    inflight.release();
                    let _ = response.send(result);
                }
                if let Some(command) = deferred {
                    match command {
                        ReceiptCommitCommand::Shutdown { response } => {
                            let _ = response.send(());
                            return;
                        }
                        other => handle_non_append_command(
                            &pool,
                            &mut head_state,
                            incremental_verification,
                            &health,
                            &mut checkpoint_signer,
                            &mut pending_flush_error,
                            other,
                        ),
                    }
                }
            }
            ReceiptCommitCommand::Flush { response, inflight } => {
                let result = match &pending_flush_error {
                    Some(error) => Err(receipt_store_error_snapshot(error)),
                    None => Ok(()),
                };
                if result.is_ok() {
                    health.note_maintenance_success();
                }
                inflight.release();
                let _ = response.send(result);
            }
            ReceiptCommitCommand::ShutdownFlush { response, inflight } => {
                let result = match &pending_flush_error {
                    Some(error) => Err(receipt_store_error_snapshot(error)),
                    None => retry_owed_checkpoints_for_shutdown(
                        &pool,
                        &mut head_state,
                        &checkpoint_signer,
                        &health,
                    ),
                };
                if result.is_ok() {
                    health.note_maintenance_success();
                }
                inflight.release();
                let _ = response.send(result);
            }
            ReceiptCommitCommand::Shutdown { response } => {
                let _ = response.send(());
                return;
            }
            other => handle_non_append_command(
                &pool,
                &mut head_state,
                incremental_verification,
                &health,
                &mut checkpoint_signer,
                &mut pending_flush_error,
                other,
            ),
        }
    }
}

/// Publish a writer-head integrity failure before replying to the command that
/// detected it. The health bit is the pre-dispatch gate's cross-thread signal;
/// the local state rejects commands that were already queued behind the failing
/// command.
fn publish_writer_head_poison(
    health: &ReceiptCommitWriterHealth,
    head_state: &mut WriterHeadState,
    error: &ReceiptStoreError,
) {
    let message = error.to_string();
    health.set_head_poisoned(true);
    *head_state = WriterHeadState::Poisoned(message.clone());
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = Some(message);
    }
}

/// Rotation can fail for ordinary operator or storage reasons that do not
/// establish corruption (for example, an invalid archive target or an I/O
/// failure). Poison only errors that prove retained evidence no longer matches
/// the integrity contract.
fn rotation_error_indicates_integrity_failure(error: &ReceiptStoreError) -> bool {
    match error {
        ReceiptStoreError::RetentionArchiveIncomplete { .. }
        | ReceiptStoreError::RetentionWatermarkRegression { .. }
        | ReceiptStoreError::ArchivedRangeProjection { .. }
        | ReceiptStoreError::Json(_)
        | ReceiptStoreError::CryptoDecode(_)
        | ReceiptStoreError::Canonical(_) => true,
        ReceiptStoreError::Conflict(message) => {
            message.starts_with("retention archive no longer backs the committed watermark")
                || message.starts_with("checkpoint ")
                || message.starts_with("first checkpoint ")
        }
        _ => false,
    }
}

fn handle_non_append_command(
    pool: &Pool<ReceiptConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    health: &Arc<ReceiptCommitWriterHealth>,
    checkpoint_signer: &mut Option<BackgroundCheckpointSigner>,
    pending_flush_error: &mut Option<ReceiptStoreError>,
    command: ReceiptCommitCommand,
) {
    match command {
        ReceiptCommitCommand::Write {
            job,
            appends_receipts,
            inflight: inflight_lease,
        } => {
            // Hold the writer `inflight` count for the DURATION of this Write
            // job rather than releasing it immediately on dequeue, so a health
            // poll during a slow or stuck liability/checkpoint write reports
            // `inflight > 0`. The pre-send increment in
            // `WriterHandle::run_write_kind` is owned by this command lease.
            //
            // `finish_write_response` first publishes the resync-adjusted
            // committed/failed outcome and command-specific health state, then
            // releases the lease, then delivers the prepared response. A caller
            // that observes its response therefore sees terminal accounting and
            // never sees itself still counted inflight. The lease stays live
            // through the job body and head resync, while Drop backstops any
            // panic before finalization. The caller's paired release handle
            // shares the same exact-once state, so channel loss cannot consume
            // another command's count.
            let mut connection = match pool.get() {
                Ok(connection) => connection,
                Err(error) => {
                    // No write ran (no connection), so there is no resync to
                    // gate on: send the pool error now (`Ok(())` = nothing to
                    // override). Count the failed outcome.
                    let respond = job(Err(ReceiptStoreError::Pool(error.to_string())));
                    finish_write_response(health, inflight_lease, respond, Ok(()), || {});
                    return;
                }
            };
            match head_state {
                WriterHeadState::Poisoned(message) => {
                    let respond = job(Err(poisoned_head_error(message)));
                    finish_write_response(health, inflight_lease, respond, Ok(()), || {});
                }
                WriterHeadState::Verified(head) => {
                    // Pre-check (fail-closed): same predecessor check the
                    // append path runs, so writer-routed appends (child
                    // receipts, consuming auth) are equally protected. On the
                    // non-incremental (full-verification) fallback, a
                    // receipt-appending job also runs the full claim-log
                    // validation, so uncheckpointed projection drift is caught
                    // before the
                    // write commits. Metadata-only Write jobs skip the O(N)
                    // scan.
                    let pre_check = if incremental_verification {
                        // Verify the checkpoint head, THEN validate the adopted
                        // claim-log delta before the job commits: a
                        // receipt-appending writer job must reject a
                        // stale/invalid baseline BEFORE its durable insert, the
                        // same way the append path does, not durably write and
                        // only poison the head in the post-write resync.
                        match verify_head_against_latest_checkpoint(&connection, head) {
                            Ok(()) => validate_writer_adopted_claim_log_baseline(
                                &connection,
                                head,
                                appends_receipts,
                            ),
                            Err(error) => Err(error),
                        }
                    } else {
                        verify_latest_checkpoint_integrity(&connection).and_then(|()| {
                            if appends_receipts {
                                validate_claim_receipt_log_entries(&connection)
                            } else {
                                Ok(())
                            }
                        })
                    };
                    if let Err(error) = pre_check {
                        publish_writer_head_poison(health, head_state, &error);
                        let respond = job(Err(error));
                        finish_write_response(health, inflight_lease, respond, Ok(()), || {});
                        return;
                    }
                    // Capture the head's checkpoint position BEFORE the job
                    // runs: a writer-routed recovery
                    // (`create_next_receipt_checkpoint`) that creates/adopts the
                    // missing checkpoint advances this during the resync below.
                    let pre_checkpoint_seq = head.checkpoint_seq();
                    // Run the job but DEFER its response: the caller must not
                    // observe `Ok` until
                    // `resync_head_after_write` confirms the head. A committed
                    // write whose resync then fails receives the resync error,
                    // not a stale `Ok`.
                    let respond = job(Ok(&mut connection));
                    // Post-resync: absorb whatever the closure committed
                    // (claim-log rows via projection triggers, checkpoint
                    // rows via the manual path) so the next append's
                    // cross-check cannot false-Conflict.
                    match resync_head_after_write(&connection, head) {
                        Ok(()) => {
                            // If a signer is active, checkpoint catch-up remains
                            // synchronous after this Write response. Reserve an
                            // actor-activity lease before finalization releases
                            // the command lease, so a stalled builder cannot make
                            // the sole writer appear idle to pre-dispatch health.
                            let checkpoint_activity = if (incremental_verification
                                || appends_receipts)
                                && checkpoint_signer
                                    .as_ref()
                                    .is_some_and(|signer| signer.max_batch > 0)
                            {
                                Some(WriterInflightLease::acquire(health).0)
                            } else {
                                None
                            };
                            // Publish counters, the resynced head snapshot, and
                            // any recovery error clear before releasing the lease
                            // and delivering the caller response. The post-response
                            // catch-up build below reads no inflight state.
                            finish_write_response(
                                health,
                                inflight_lease,
                                respond,
                                Ok(()),
                                || {
                                    health.store_head_snapshot(head);
                                    // Clear a stale checkpoint error after a
                                    // manual recovery. A writer-routed op such as
                                    // `create_next_receipt_checkpoint` can advance
                                    // the checkpoint during resync while the due
                                    // builder below finds no remaining work. Clear
                                    // only on a real advance; a later build failure
                                    // records a fresh error.
                                    if head.checkpoint_seq() > pre_checkpoint_seq {
                                        if let Ok(mut last_error) = health.last_error.lock() {
                                            *last_error = None;
                                        }
                                    }
                                }
                            );
                            // Writer-routed appends (child receipts, consuming
                            // auth) can cross the threshold too; no
                            // pending_flush_error guard here since a Write job is
                            // not part of a batch. The writer pool holds exactly
                            // one connection (DEFAULT_WRITER_POOL_MAX_SIZE = 1):
                            // drop this one before build_due_checkpoints_and_record
                            // acquires its own, or `pool.get()` would block on
                            // itself.
                            drop(connection);
                            // Gate the catch-up build on a full-verified head,
                            // mirroring the InstallSigner defer. On a
                            // non-incremental (suspect)
                            // store `seed_head_snapshot` leaves the head
                            // UNVALIDATED; only a receipt-appending Write reran the
                            // full claim-log validation in the pre-check above, so
                            // a metadata-only `run_write` did NOT. Building here
                            // would checkpoint unaudited claim-log rows before the
                            // deferred full validation ever runs (fail-closed
                            // violation). Build only when the head is genuinely
                            // verified: incremental mode (seed_verified_head +
                            // per-append verify) OR a receipt-appending job that
                            // just ran the full validation.
                            if incremental_verification || appends_receipts {
                                build_due_checkpoints_and_record(
                                    pool,
                                    head,
                                    checkpoint_signer,
                                    health,
                                );
                            }
                            drop(checkpoint_activity);
                        }
                        Err(error) => {
                            // Surface the resync failure to the caller: a write
                            // that returned `Ok` from its closure must NOT report
                            // success when the head is now poisoned. Publish the
                            // poison and failed outcome before releasing the
                            // lease and delivering the response.
                            publish_writer_head_poison(health, head_state, &error);
                            finish_write_response(
                                health,
                                inflight_lease,
                                respond,
                                Err(error),
                                || {},
                            );
                        }
                    }
                }
            }
        }
        ReceiptCommitCommand::Rotate {
            config,
            response,
            inflight: inflight_lease,
        } => {
            // Adopt the pre-send increment for the full rotation. Releasing on
            // dequeue would let a slow archive copy or locked delete disappear
            // from writer health while it still owns the single writer.
            // Fail-closed: rotation deletes evidence, so it must never run on a
            // store whose chain integrity is unverified. Refuse on a poisoned
            // head (mirrors the Write arm) and point at the repair path.
            if let WriterHeadState::Poisoned(message) = head_state {
                inflight_lease.release();
                let _ = response.send(Err(poisoned_head_error(message)));
                return;
            }
            let mut connection = match pool.get() {
                Ok(connection) => connection,
                Err(error) => {
                    inflight_lease.release();
                    let _ = response.send(Err(ReceiptStoreError::Pool(error.to_string())));
                    return;
                }
            };
            // Fail-closed: rotation deletes evidence, so it must audit the FULL
            // persisted checkpoint chain against the live claim log before pruning,
            // in BOTH verification modes. A non-incremental store seeds its head
            // via `seed_head_snapshot`, which defers the checkpoint-chain audit to
            // the next append, so its Verified state is not proof of integrity. An
            // incremental store maintains a per-append verified head, but that head
            // only attests NEW appends: it never notices a retroactive deletion of
            // a checkpoint-covered source row AND its claim-log projection row after
            // the store was opened. That drift leaves the source and projection sets
            // matching (so the projection audit below passes) while the covering
            // checkpoint's claim-log range falls short of its signed tree_size, and
            // rotating over it would co-archive only the survivors, delete the rest,
            // and stamp a watermark the archive cannot back. The full chain audit
            // rejects exactly that. Rotation is off the append hot path, so the O(N)
            // rebuild is affordable here even in incremental mode.
            let verified_latest_checkpoint = match verify_checkpoint_chain_integrity(&connection) {
                Ok(latest) => latest,
                Err(error) => {
                    publish_writer_head_poison(health, head_state, &error);
                    inflight_lease.release();
                    let _ = response.send(Err(error));
                    return;
                }
            };
            // The claim-log projection audit runs before EVERY rotation,
            // regardless of verification mode. A store in the drift shape (source
            // receipts deleted but their claim-log rows left behind, the shape
            // `retention_repair` recovers from) is NOT caught by the per-append
            // verified head an incremental store maintains: that head verifies new
            // appends, never a retroactive source-row deletion. Rotating over such
            // a store would co-archive orphaned claim-log rows without their
            // receipts (`verify_co_archival_complete` only compares surviving
            // source rows) and then delete the live claim log, destroying the
            // evidence repair needs to recover. Refuse fail-closed instead.
            if let Err(error) = validate_claim_receipt_log_entries(&connection) {
                publish_writer_head_poison(health, head_state, &error);
                inflight_lease.release();
                let _ = response.send(Err(error));
                return;
            }
            // In incremental mode the rotation trusts the per-append verified head
            // rather than an O(N) rebuild on the append hot path, but that head can
            // lag `kernel_checkpoints`: a second store instance or an operator
            // import may have appended checkpoint rows this handle has not yet
            // adopted, so `head.checkpointed_entry_seq()` stays at the boundary the
            // head was seeded at until a later append catches it up. Capping the
            // archival watermark at that stale boundary would make a quiet store
            // archive nothing on every retention interval despite holding aged,
            // checkpointed receipts. The full chain audit just above validated
            // every persisted checkpoint, so cap instead at the freshest VERIFIED
            // boundary: the latest persisted checkpoint's batch_end_seq (pinned
            // from that audit, so a checkpoint appended after it cannot widen the
            // cap). Non-incremental mode runs the same audit in its rotation path
            // and computes the watermark from every persisted checkpoint, so it
            // needs no cap.
            let verified_ceiling = if incremental_verification {
                Some(
                    verified_latest_checkpoint
                        .as_ref()
                        .map_or(0, |checkpoint| checkpoint.body.batch_end_seq),
                )
            } else {
                None
            };
            // Panic isolation: the writer actor re-acquires a fresh connection
            // for every command, so a caught panic fails only THIS rotation
            // (fail-closed) and no state from the panicking closure is reused
            // afterward.
            let (outcome, rotation_panicked) =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    evidence_retention::rotate_on_writer_connection(
                        &mut connection,
                        &config,
                        verified_ceiling,
                    )
                })) {
                    Ok(outcome) => (outcome, false),
                    Err(payload) => (Err(receipt_writer_job_panic_error(&payload)), true),
                };
            if let Err(error) = &outcome {
                if rotation_panicked || rotation_error_indicates_integrity_failure(error) {
                    publish_writer_head_poison(health, head_state, error);
                }
            }
            // After a successful bottom-of-log delete the cached head's
            // latest_checkpoint and claim_log_max_seq are unchanged (rotation
            // never deletes checkpoints and never touches the max entry_seq),
            // but claim_log_count shrank. Refresh it so diagnostics stay
            // accurate; correctness does not depend on this (no hot path
            // asserts count equality).
            if outcome.is_ok() {
                if let WriterHeadState::Verified(head) = head_state {
                    if let Ok((count, max_seq)) = claim_log_delta_count_and_max_seq(&connection, 0)
                    {
                        head.claim_log_count = count;
                        head.claim_log_max_seq = max_seq;
                    }
                    health.store_head_snapshot(head);
                }
                health.note_maintenance_success();
            }
            inflight_lease.release();
            let _ = response.send(outcome);
        }
        ReceiptCommitCommand::InstallSigner {
            signer,
            inflight: inflight_lease,
        } => {
            *checkpoint_signer = Some(signer);
            // Install-time catch-up. The store can
            // open on a DB that already has >= max_batch uncheckpointed
            // claim-log entries (a crash between the durable append response and
            // the background build, or enabling checkpointing on an existing
            // store). Without building here, the owed checkpoint waits for some
            // future Append/Write, so a quiet restarted store stays
            // uncheckpointed indefinitely despite checkpointing being enabled.
            // Run the existing bounded builder now so any already-owed
            // checkpoints (head.claim_log_max_seq - checkpointed_entry_seq >=
            // max_batch) are built at install time (O(b) per checkpoint, loops
            // until caught up; NOT a full verify). Fail-closed:
            // build_due_checkpoints_and_record records last_error and never
            // panics the actor.
            //
            // Deferred-seed gate: only build at
            // install when the head has actually been VALIDATED. With
            // `incremental_verification = false` the actor seeds via
            // `seed_head_snapshot`, which INTENTIONALLY skips the full claim-log
            // + checkpoint-chain audit (deferred to the next append/verify), so
            // the seeded head is `Verified` but UNVALIDATED. Building catch-up
            // checkpoints over that range would checkpoint unaudited data (a
            // fail-closed violation), so defer it in that mode: the next
            // receipt-appending append/Write runs the deferred full validation
            // and THEN builds the owed checkpoints. In the normal incremental
            // mode the seeded head is genuinely verified, so the owed
            // checkpoints still build here.
            if incremental_verification {
                if let WriterHeadState::Verified(head) = head_state {
                    build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                }
            }
            health.note_maintenance_success();
            inflight_lease.release();
        }
        ReceiptCommitCommand::ReseedHead {
            response,
            inflight: inflight_lease,
        } => {
            let outcome = pool
                .get()
                .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
                .and_then(|connection| {
                    #[cfg(test)]
                    test_hooks::block_during_reseed(&connection);
                    // Reseed always runs the FULL verification. This is the
                    // `chio receipt audit --repair`
                    // recovery path: it clears a poisoned head and must establish
                    // a genuinely CLEAN, fully-verified head, so it runs
                    // `seed_verified_head` (full claim-log validation +
                    // checkpoint-chain audit) regardless of the hot-path
                    // `incremental_verification` mode. Using the cheap
                    // `seed_head_snapshot` here would let `--repair` clear
                    // `last_error` and mark the head `Verified` while the on-disk
                    // log is still corrupt (repair theater). This is the recovery
                    // path, not per-append, so it is a recovery-path cost. NOTE
                    // the deliberate difference from the InstallSigner catch-up:
                    // that path DEFERS in
                    // `incremental_verification = false` because `seed_head_snapshot`
                    // leaves the head UNVALIDATED; reseed full-verifies, so it does
                    // not defer.
                    seed_verified_head(&connection)
                });
            let result = match outcome {
                Ok(head) => {
                    health.store_head_snapshot(&head);
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = None;
                    }
                    // Clear the actor loop's stale flush error: a prior append
                    // poisoned the head and set
                    // `pending_flush_error`, but this reseed has just revalidated
                    // the DB and replaced the head. Without clearing it, a
                    // subsequent STANDALONE `flush_receipt_writes()` (no queued
                    // writes) would keep returning the stale append error even
                    // though the store recovered. Fail-closed is unaffected: a
                    // real later batch failure re-sets `pending_flush_error`.
                    *pending_flush_error = None;
                    health.set_head_poisoned(false);
                    *head_state = WriterHeadState::Verified(Box::new(head));
                    // Build owed checkpoints after a successful reseed. If the
                    // background signer was installed
                    // while the head was poisoned, its install-time catch-up
                    // was skipped, so a quiet store with >= max_batch
                    // uncheckpointed claim-log entries would stay uncheckpointed
                    // until some future write. Run the SAME bounded builder now.
                    // Unlike the InstallSigner catch-up (which gates on
                    // `incremental_verification` because its deferred seed is
                    // unvalidated), this is unconditional: the reseed just
                    // full-verified the head, so building over that range never
                    // checkpoints unaudited data. Bounded (O(b) per owed
                    // checkpoint), a recovery-path build (not per-append).
                    // No-op when no signer is present. Fail-closed:
                    // `build_due_checkpoints_and_record` records `last_error` on a
                    // build failure and never re-poisons the freshly verified head.
                    if let WriterHeadState::Verified(head) = head_state {
                        build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                    }
                    Ok(())
                }
                Err(error) => {
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = Some(error.to_string());
                    }
                    health.set_head_poisoned(true);
                    *head_state = WriterHeadState::Poisoned(error.to_string());
                    Err(error)
                }
            };
            if result.is_ok() {
                health.note_maintenance_success();
            }
            inflight_lease.release();
            let _ = response.send(result);
        }
        ReceiptCommitCommand::RetentionRepair {
            archive_path,
            response,
            inflight: inflight_lease,
        } => {
            // Retain the pre-send increment through the repair and the full
            // verified-head reseed. Both steps own the single writer and must
            // remain visible to the liveness classifier until completion.
            // Runs regardless of `head_state` (like ReseedHead): the whole
            // point of this command is to repair a store whose head is
            // already Poisoned by the drift the repair removes, so gating it
            // on `WriterHeadState::Verified` (the Write arm's head check) would
            // make it unusable on exactly the store it exists to fix.
            let repair_outcome = pool
                .get()
                .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
                .and_then(|mut connection| {
                    evidence_retention::retention_repair_on_writer(&mut connection, &archive_path)
                });
            let outcome = match repair_outcome {
                Ok(removed) => {
                    // Repair is an integrity-recovery path, so its success is not
                    // complete until a FULL verified seed succeeds. This is
                    // unconditional in both hot-path verification modes.
                    let reseed = pool
                        .get()
                        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
                        .and_then(|connection| seed_verified_head(&connection));
                    match reseed {
                        Ok(head) => {
                            health.store_head_snapshot(&head);
                            if let Ok(mut last_error) = health.last_error.lock() {
                                *last_error = None;
                            }
                            // Clear the actor loop's stale flush error, mirroring the
                            // ReseedHead recovery path: if an earlier append poisoned
                            // the head and set `pending_flush_error`, the repair has
                            // now reseeded a revalidated head, so a subsequent
                            // STANDALONE `flush_receipt_writes()` must not keep
                            // returning the pre-repair append error. Fail-closed is
                            // unaffected: a real later batch failure re-sets it.
                            *pending_flush_error = None;
                            health.set_head_poisoned(false);
                            *head_state = WriterHeadState::Verified(Box::new(head));
                            Ok(removed)
                        }
                        Err(error) => {
                            publish_writer_head_poison(health, head_state, &error);
                            Err(error)
                        }
                    }
                }
                Err(error) => Err(error),
            };
            if outcome.is_ok() {
                health.note_maintenance_success();
            }
            inflight_lease.release();
            let _ = response.send(outcome);
        }
        // Append/Flush are handled by the main loop; reaching here is
        // impossible by construction but must stay fail-safe.
        ReceiptCommitCommand::Append { request, inflight } => {
            inflight.release();
            let _ = request
                .response
                .send(Err(receipt_actor_unavailable_error()));
        }
        ReceiptCommitCommand::Flush { response, inflight } => {
            inflight.release();
            let _ = response.send(Err(receipt_actor_unavailable_error()));
        }
        ReceiptCommitCommand::ShutdownFlush { response, inflight } => {
            inflight.release();
            let _ = response.send(Err(receipt_actor_unavailable_error()));
        }
        ReceiptCommitCommand::Shutdown { response } => {
            let _ = response.send(());
        }
    }
}

/// Build every checkpoint the head owes and, on success, refresh the health
/// head snapshot; on failure, record the error without poisoning the head or
/// failing the append/write that triggered it (checkpoint construction never
/// blocks an already-durable commit). Returns the recorded
/// error (if any) so a flush-as-checkpoint-barrier caller can surface it to its
/// co-drained flush waiters; the durable append/write path ignores the return
/// and stays fail-closed via `last_error`.
fn build_due_checkpoints_and_record(
    pool: &Pool<ReceiptConnectionManager>,
    head: &mut VerifiedHead,
    checkpoint_signer: &Option<BackgroundCheckpointSigner>,
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let signer = checkpoint_signer.as_ref()?;
    // Panic isolation: a panic mid-build
    // (Merkle build, Ed25519 sign, serde) must not kill the writer thread.
    // A committed or peer-adopted checkpoint can advance the verified head
    // before a later panic drops its frontier. Record `last_error` and rebuild.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_due_checkpoints(pool, head, signer)
    }))
    .unwrap_or_else(|payload| Err(receipt_writer_job_panic_error(&payload)));
    match result {
        Ok(advanced) => {
            health.store_head_snapshot(head);
            health.resolve_owed_checkpoint_error(head.checkpointed_entry_seq());
            // Clear a stale background error only after this attempt advances
            // the verified head. An idle refresh must not mask a current error.
            if advanced {
                if let Ok(mut last_error) = health.last_error.lock() {
                    *last_error = None;
                }
            }
            None
        }
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
            let checkpointed_entry_seq = head.checkpointed_entry_seq();
            let uncheckpointed_entries = head
                .claim_log_max_seq
                .saturating_sub(checkpointed_entry_seq);
            let owed_batches = if signer.max_batch == 0 {
                0
            } else {
                uncheckpointed_entries / signer.max_batch
            };
            let owed_target = (owed_batches > 0).then(|| {
                checkpointed_entry_seq
                    .saturating_add(owed_batches.saturating_mul(signer.max_batch))
            });
            if let Some(required_checkpointed_entry_seq) = owed_target {
                health.record_owed_checkpoint_error(&error, required_checkpointed_entry_seq);
            }
            Some(error)
        }
    }
}

fn retry_owed_checkpoints_for_shutdown(
    pool: &Pool<ReceiptConnectionManager>,
    head_state: &mut WriterHeadState,
    checkpoint_signer: &Option<BackgroundCheckpointSigner>,
    health: &ReceiptCommitWriterHealth,
) -> Result<(), ReceiptStoreError> {
    let Some(owed_error) = health.owed_checkpoint_error()? else {
        return Ok(());
    };
    let WriterHeadState::Verified(head) = head_state else {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store close refused with owed checkpoint work through entry {}: {}",
            owed_error.required_checkpointed_entry_seq, owed_error.message
        )));
    };
    match build_due_checkpoints_and_record(pool, head, checkpoint_signer, health) {
        Some(error) => Err(error),
        None => match health.owed_checkpoint_error()? {
            Some(error) => Err(ReceiptStoreError::Conflict(format!(
                "sqlite receipt store close refused with owed checkpoint work through entry {}: {}",
                error.required_checkpointed_entry_seq, error.message
            ))),
            None => Ok(()),
        },
    }
}

fn build_due_checkpoints(
    pool: &Pool<ReceiptConnectionManager>,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<bool, ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(false); // ADR-0008: batch_size 0 disables checkpointing
    }
    let mut connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    let checkpoint_seq_before_refresh = head.checkpoint_seq();
    // Shared-file freshness: on a shared receipt DB
    // another writer can commit a checkpoint AFTER this actor's append
    // pre-check but BEFORE its batch tx. `append_receipt_batch` then adopts that
    // writer's claim-log rows via the baseline delta yet leaves
    // `head.latest_checkpoint` stale, so building from the stale position would
    // try to rebuild an already-committed checkpoint and fail with "already
    // exists with different content" (the clock-skew case the idempotent-
    // identical guard does not cover). Refresh the head against the latest
    // persisted checkpoint first so that checkpoint is ADOPTED, not rebuilt.
    // This is an O(1) latest-row read + digest adopt (plus bounded catch-up),
    // NOT a full chain verify, so the incremental hot path stays flat per
    // append.
    verify_head_against_latest_checkpoint(&connection, head)?;
    let refreshed = head.checkpoint_seq() > checkpoint_seq_before_refresh;
    maybe_build_checkpoint(&mut connection, head, signer).map(|advanced| refreshed || advanced)
}

/// Build every checkpoint the head owes: count-based ADR-0008 trigger, range
/// derived from the cached head (NOT next_checkpoint_range_for_connection,
/// which runs a full chain verify). Cost is O(b) over the receipt batch plus
/// O(log n) over the cached checkpoint-chain frontier.
fn maybe_build_checkpoint(
    connection: &mut SqliteStoreConnection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<bool, ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(false);
    }
    if head
        .claim_log_max_seq
        .saturating_sub(head.checkpointed_entry_seq())
        < signer.max_batch
    {
        return Ok(false);
    }
    let cached = head
        .chain_frontier
        .as_ref()
        .filter(|frontier| frontier.leaf_count() == head.checkpoint_seq())
        .cloned();
    let mut advanced = false;
    let mut chain_frontier = match cached {
        Some(frontier) => frontier,
        None => {
            let (frontier, cache_advanced) =
                build_checkpoint_after_frontier_cache_miss(connection, head, signer)?;
            advanced = cache_advanced;
            frontier
        }
    };
    if chain_frontier.leaf_count() != head.checkpoint_seq() {
        return Err(ReceiptStoreError::Conflict(format!(
            "persisted chain covers {} checkpoints but the head is at {}",
            chain_frontier.leaf_count(),
            head.checkpoint_seq()
        )));
    }
    while head
        .claim_log_max_seq
        .saturating_sub(head.checkpointed_entry_seq())
        >= signer.max_batch
    {
        let start_seq = head.checkpointed_entry_seq().saturating_add(1);
        let end_seq = start_seq.saturating_add(signer.max_batch - 1);
        ensure_claim_log_range_contiguous(connection, start_seq, end_seq, "checkpoint range")?;
        let receipt_bytes = load_claim_tree_canonical_bytes_range(connection, start_seq, end_seq)?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = head
            .checkpoint_seq()
            .checked_add(1)
            .ok_or_else(|| ReceiptStoreError::Conflict("checkpoint_seq overflow".to_string()))?;
        // The pluggable signer preserves HSM/keyring authority while the
        // frontier binds the complete checkpoint history.
        let checkpoint = chio_kernel::build_checkpoint_with_backend(
            checkpoint_seq,
            start_seq,
            end_seq,
            &receipt_bytes,
            signer.backend.as_ref(),
            head.latest_checkpoint.as_ref(),
            &chain_frontier,
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        #[cfg(test)]
        if test_hooks::panic_during_checkpoint_build(signer.max_batch) {
            panic!("injected test panic during background checkpoint build");
        }
        #[cfg(test)]
        if test_hooks::fail_checkpoint_build(signer.max_batch) {
            return Err(ReceiptStoreError::Conflict(
                "injected test checkpoint build failure".to_string(),
            ));
        }
        #[cfg(test)]
        test_hooks::block_during_checkpoint_build(signer.max_batch);
        // The insert returns the checkpoint now persisted at this seq: either
        // the one we just built, or a concurrently committed winner (clock-skew
        // sibling) it validated and adopted. Catch the cached head up to THAT
        // checkpoint so a later verify_head_against_latest_checkpoint does not
        // see our discarded byte-different build diverge from the persisted row.
        let (adopted, adopted_frontier) = insert_background_checkpoint_guarded(
            connection,
            head.latest_checkpoint.as_ref(),
            &chain_frontier,
            &checkpoint,
        )?;
        chain_frontier = adopted_frontier;
        head.latest_checkpoint = Some(adopted);
        advanced = true;
    }
    head.chain_frontier = Some(chain_frontier);
    Ok(advanced)
}

/// Head-resync rule: one indexed delta aggregate plus one
/// latest-checkpoint row read after every Write closure.
fn resync_head_after_write(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let pre_resync_max = head.claim_log_max_seq;
    let (delta_count, post_max) = claim_log_delta_count_and_max_seq(connection, pre_resync_max)?;
    // Validate the ADOPTED resync delta before advancing the head. A Write
    // closure can commit claim_receipt_log_entries rows
    // past this actor's head (another shared-DB writer, or a receipt-appending
    // Write job), and this resync absorbs them via COUNT/MAX. Without
    // validating them, an orphan/divergent row would be trusted and later
    // appends would skip it as already-verified, so a background checkpoint
    // could cover an unaudited entry. Re-validate JUST the
    // (pre_resync_max, post_max] delta against the source receipt tables
    // (O(delta)); the full-log validator is NOT called. Single-writer common
    // case: no other writer, empty delta, no-op. Fail-closed: an
    // orphan/divergent delta returns the error, which the Write arm turns into
    // a poisoned head.
    if delta_count > 0 {
        validate_adopted_claim_log_delta(connection, pre_resync_max, post_max)?;
    }
    head.claim_log_count = head.claim_log_count.saturating_add(delta_count);
    head.claim_log_max_seq = post_max;
    verify_head_against_latest_checkpoint(connection, head)
}

fn commit_receipt_batch(
    pool: &Pool<ReceiptConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    requests: Vec<ReceiptCommitRequest>,
    inflight_leases: Vec<WriterInflightLease>,
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let batch_outcome = match head_state {
        WriterHeadState::Verified(head) => {
            match append_receipt_batch(pool, head, incremental_verification, &requests) {
                Ok(results) => {
                    health.store_head_snapshot(head);
                    Ok(results)
                }
                Err(error) => Err(error),
            }
        }
        WriterHeadState::Poisoned(message) => Ok(receipt_batch_error_results(
            requests.len(),
            poisoned_head_error(message),
        )),
    };
    let results = match batch_outcome {
        Ok(results) => results,
        Err(error) => {
            // A store-wide append fault (a failed checkpoint or predecessor
            // verification, a transaction that will not open, a disk-full commit)
            // rejects every receipt in this batch and will reject every future
            // append until an operator reseeds. Poison the head so the
            // pre-dispatch gate fails closed rather than letting tools run against
            // a store that can no longer persist their receipts.
            let message = error.to_string();
            let results = receipt_batch_error_results(requests.len(), error);
            health.set_head_poisoned(true);
            *head_state = WriterHeadState::Poisoned(message);
            results
        }
    };
    let flush_error = results
        .iter()
        .find_map(|result| result.as_ref().err().map(receipt_store_error_snapshot));
    let committed = results.iter().filter(|result| result.is_ok()).count() as u64;
    let failed = results.iter().filter(|result| result.is_err()).count() as u64;
    if committed > 0 {
        health
            .committed_total
            .fetch_add(committed, Ordering::SeqCst);
        health
            .last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    }
    if failed > 0 {
        health.failed_total.fetch_add(failed, Ordering::SeqCst);
    }
    // Preserve the group-commit barrier: every command in the durable batch is
    // released before any one caller can observe its response. Per-command
    // release handles make each decrement exact-once without changing the batch-wide
    // decrement-then-fan-out ordering.
    for inflight in inflight_leases {
        inflight.release();
    }
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = flush_error.as_ref().map(ToString::to_string);
    }
    // APPEND durability responses fan out here (ADR-0013): a durable append
    // response is never delayed by checkpoint construction. The co-drained
    // Flush waiters are released by the caller AFTER the checkpoint build, so a
    // flush is a genuine checkpoint barrier.
    for (request, result) in requests.into_iter().zip(results) {
        let _ = request.response.send(result);
    }
    flush_error
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn atomic_saturating_sub(value: &AtomicU64, amount: u64) {
    let mut current = value.load(Ordering::SeqCst);
    loop {
        let next = current.saturating_sub(amount);
        match value.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Classify commit-writer liveness from a counter snapshot. Kept pure so the
/// wedged / saturated / dead transitions are unit-testable without a live actor.
///
/// - `Dead`: the actor channel has disconnected (its last error reports the
///   writer unavailable). Nothing can drain, so admission must stop.
/// - `Wedged`: work is still queued or running (`inflight > 0`, or more appends
///   were accepted than have completed) and no progress has been made within
///   `stall_threshold_ms`. The stall clock is anchored to the more recent of the
///   last commit and the start of the current backlog, so a writer that wedges
///   before its first commit is caught, while a writer resuming after an idle
///   period (an old last commit but freshly enqueued work) is measured from that
///   fresh work rather than judged wedged the instant it accepts. A bounded wait
///   that times out marks its still-live command in `timed_out_inflight`, which
///   reports Wedged immediately without claiming terminal failure.
/// - `Saturated`: the commit channel is full right now (`queue_depth` has
///   reached the channel capacity), so the next send would be rejected. This
///   reads `queue_depth` rather than `inflight` so a drained but still-committing
///   batch, whose slots are already free, does not read as a full channel and
///   deny admission when the next append would in fact be accepted. Deny
///   admission rather than run a side effect whose receipt cannot be enqueued.
/// - `Healthy`: none of the above.
fn classify_writer_liveness(
    counters: &ReceiptWriterCounters,
    stall_threshold_ms: u64,
    channel_capacity: u64,
    backlog_started_unix_ms: Option<u64>,
    now_unix_ms: u64,
) -> chio_kernel::ReceiptWriterLiveness {
    use chio_kernel::ReceiptWriterLiveness as Liveness;
    if counters
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("unavailable"))
    {
        return Liveness::Dead;
    }
    // A bounded receipt operation that exceeded its budget is direct evidence
    // the writer did not drain within budget. Its command-scoped timeout marker
    // is stronger and earlier than the heuristic stall clock, so admission stops
    // immediately. Terminal lease release removes the marker whether the late
    // command commits or fails, avoiding a stale global error string.
    if counters.timed_out_inflight > 0 {
        return Liveness::Wedged;
    }
    let backlogged = counters.inflight > 0
        || counters.accepted_total
            > counters
                .committed_total
                .saturating_add(counters.failed_total);
    // Anchor to the more recent of the last commit and the current backlog
    // start. Using the last commit alone marks a writer wedged after any idle
    // period (its last commit is naturally old); using the backlog start alone
    // would ignore progress a busy writer is still making.
    let progress_reference = counters
        .last_commit_unix_ms
        .into_iter()
        .chain(backlog_started_unix_ms)
        .max();
    let stalled = match progress_reference {
        Some(reference) => now_unix_ms.saturating_sub(reference) >= stall_threshold_ms,
        None => false,
    };
    if backlogged && stalled {
        return Liveness::Wedged;
    }
    if counters.queue_depth >= channel_capacity {
        return Liveness::Saturated;
    }
    Liveness::Healthy
}

/// Fold the writer-liveness verdict into the store's top-level health boolean.
/// A wedged, saturated, or dead writer makes the store unhealthy even when the
/// checkpoint chain is intact and no error has been recorded yet: the
/// pre-dispatch gate is already denying tool calls against that writer, so a
/// health surface that stayed green would contradict it. `Healthy` and the
/// permissive `Unknown` (no async writer, or a read-only observer that cannot
/// see writer liveness) do not downgrade health.
fn receipt_store_healthy(
    checkpoint_healthy: bool,
    writer_last_error: Option<&str>,
    writer_liveness: chio_kernel::ReceiptWriterLiveness,
) -> bool {
    use chio_kernel::ReceiptWriterLiveness as Liveness;
    checkpoint_healthy
        && writer_last_error.is_none()
        && !matches!(
            writer_liveness,
            Liveness::Wedged | Liveness::Saturated | Liveness::Dead
        )
}
