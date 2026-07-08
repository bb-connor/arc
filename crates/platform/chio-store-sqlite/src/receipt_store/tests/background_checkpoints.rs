use super::super::*;
use super::support::*;

fn signer(keypair: &Keypair, max_batch: u64) -> BackgroundCheckpointSigner {
    BackgroundCheckpointSigner {
        keypair: Arc::new(keypair.clone()),
        max_batch,
    }
}

/// RFC-0006 whole-store-death fix: a panic mid checkpoint-build (Merkle
/// build, Ed25519 sign, serde) must not kill the writer thread and must not
/// leave `head.latest_checkpoint` pointing at a half-built checkpoint. Uses
/// the `test_hooks::PANIC_DURING_CHECKPOINT_BUILD` fault hook, which fires
/// after the checkpoint body is computed but before its write transaction
/// opens (`maybe_build_checkpoint`), mirroring the Task 9/10 fault-hook
/// pattern used elsewhere in this suite.
///
/// This crate's tests run in parallel and the fault-hook flag is
/// process-global, so this test uses
/// `PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH` as its `max_batch`: the
/// hook only fires for a signer using that exact (otherwise unused) batch
/// size, so a concurrently running, unrelated background-checkpoint test
/// cannot be hit by this test's injected panic.
#[test]
fn background_build_panic_is_isolated() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-panic-isolated");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = test_hooks::PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH;
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;

    test_hooks::PANIC_DURING_CHECKPOINT_BUILD.store(true, std::sync::atomic::Ordering::SeqCst);
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-bg-panic-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    // Flush is the synchronization barrier: the actor attempts the
    // checkpoint build inside the same command iteration as the batch that
    // crosses the threshold, and a Flush enqueued afterwards is only served
    // once that iteration (panic included) finishes.
    store.flush_receipt_writes()?;
    test_hooks::PANIC_DURING_CHECKPOINT_BUILD.store(false, std::sync::atomic::Ordering::SeqCst);

    // last_error records the caught panic; no checkpoint was persisted
    // (head.latest_checkpoint stayed unassigned: the panic fires before the
    // write transaction opens).
    let health = store.receipt_store_health()?;
    let last_error = health.writer.last_error.as_deref().unwrap_or_default();
    assert!(
        last_error.contains("receipt writer job panicked"),
        "expected last_error to record the injected panic, got {last_error:?}"
    );
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "a panic mid-build must not leave a partially built checkpoint"
    );
    // `receipt_store_health` folds `writer.last_error.is_some()` into
    // `healthy` (same as a non-panic checkpoint-build `Err` would), so the
    // caught panic is visible here too -- it is NOT swallowed. This is
    // distinct from head poisoning, which is proven below by the recovery
    // append succeeding (a poisoned head fails every subsequent write).
    assert!(
        !health.healthy,
        "a recorded writer error must still surface through receipt_store_health"
    );

    // Teeth: the writer thread survived AND the head was not poisoned. The
    // next append (now with the injected panic off) still succeeds and
    // builds the checkpoint the earlier, panic-interrupted attempt owed;
    // the batch commit that carries it also clears `last_error`.
    let receipt = sample_receipt_with_keypair("rcpt-bg-panic-recovery", max_batch + 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "writer thread must still be alive and able to build checkpoints after the panic"
    );
    let recovered_health = store.receipt_store_health()?;
    assert!(
        recovered_health.healthy,
        "a successful batch after the panic must clear last_error: {recovered_health:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn maybe_build_checkpoint_builds_one_checkpoint_per_crossed_threshold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-threshold");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 3))?;

    // 7 appends with max_batch 3: exactly two checkpoints (1..=3, 4..=6);
    // entry 7 stays uncheckpointed (partial final batch, ADR-0008).
    for i in 0..7 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    // Flush is the synchronization barrier: the actor builds checkpoints
    // inside the same command iteration as the batch commit, and a Flush
    // enqueued afterwards is only served once that iteration finishes.
    store.flush_receipt_writes()?;

    let first = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let second = store
        .load_checkpoint_by_seq(2)?
        .ok_or("checkpoint 2 missing")?;
    assert!(
        store.load_checkpoint_by_seq(3)?.is_none(),
        "no third checkpoint yet"
    );
    assert_eq!(
        (first.body.batch_start_seq, first.body.batch_end_seq),
        (1, 3)
    );
    assert_eq!(
        (second.body.batch_start_seq, second.body.batch_end_seq),
        (4, 6)
    );
    // previous_checkpoint_sha256 links to the head's cached predecessor.
    let expected_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&first.body)?;
    assert_eq!(
        second.body.previous_checkpoint_sha256.as_deref(),
        Some(expected_digest.as_str())
    );
    assert!(first.body.previous_checkpoint_sha256.is_none());

    // The full audit surface agrees (chain + projections all valid).
    let status = store.receipt_checkpoint_status(Some(3))?;
    assert!(
        status.healthy,
        "audit after background checkpoints: {status:?}"
    );
    assert_eq!(status.latest_checkpoint_seq, Some(2));
    assert_eq!(status.latest_checkpointed_entry_seq, 6);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn zero_max_batch_disables_background_checkpointing() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-disabled");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 0))?;
    for i in 0..5 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-off-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "batch_size 0 disables checkpoints"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn one_big_batch_crossing_two_thresholds_builds_both_checkpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-multicross");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    // 4 appends may commit as ONE group-commit batch; the while-loop in
    // maybe_build_checkpoint must still emit checkpoints 1..=2 and 3..=4.
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-multi-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());
    assert!(store.load_checkpoint_by_seq(2)?.is_some());
    assert!(store.load_checkpoint_by_seq(3)?.is_none());
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn background_and_writer_routed_child_appends_share_the_threshold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-child");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    let receipt = sample_receipt_with_keypair("rcpt-bg-child-0", 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    let child = sample_child_receipt_with_keypair_and_timestamp("child-bg-1", 2, &keypair);
    store.append_child_receipt_record(&child)?; // writer-routed, claim-log row 2
    store.flush_receipt_writes()?;
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("child append must count toward the threshold")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 2)
    );
    let _ = fs::remove_file(path);
    Ok(())
}

/// RFC-0006 idempotent background-checkpoint convergence: two kernels/store
/// instances sharing one receipt DB can each build the same due checkpoint
/// before either head catches up. The loser reaches
/// `insert_checkpoint_incremental_tx` after the winner already committed a
/// byte-identical row. It must be treated as success (like
/// `store_kernel_checkpoint_tx`), not a conflict that records
/// `writer.last_error` and reports the store UNHEALTHY even though the
/// persisted chain is valid.
#[test]
fn identical_background_checkpoint_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-idempotent");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Seed three receipts and build checkpoint 1 (batch 1..=3): the "winner".
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-idem-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let persisted = store
        .load_checkpoint_by_seq(1)?
        .ok_or("winner checkpoint 1 missing")?;

    // The "loser" rebuilds and re-inserts the byte-identical checkpoint 1.
    // Before the fix the raw INSERT hit the primary-key conflict and errored;
    // now it is adopted as success.
    {
        let mut connection = store.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_checkpoint_incremental_tx(&tx, None, &persisted)?;
        tx.commit()?;
    }

    // The persisted chain is unchanged and the full audit stays healthy: no
    // duplicate row, checkpoint head caught up at seq 1.
    let status = store.receipt_checkpoint_status(Some(3))?;
    assert!(
        status.healthy,
        "idempotent re-insert must keep the store healthy: {status:?}"
    );
    assert_eq!(status.latest_checkpoint_seq, Some(1));
    assert_eq!(status.latest_checkpointed_entry_seq, 3);
    assert!(
        store.load_checkpoint_by_seq(2)?.is_none(),
        "the idempotent re-insert must not add a second checkpoint row"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// RFC-0006 flush-report freshness: when a second handle extends the
/// checkpoint chain out of band and this handle has had no intervening append,
/// a Flush must reflect the CURRENT persisted checkpoint (read from the DB),
/// not the stale writer-head atomics that would overstate the uncheckpointed
/// range.
#[test]
fn flush_report_reflects_externally_extended_checkpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-flush-external-ckpt");
    let keypair = receipt_test_keypair();
    let store_a = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-flush-{i}"), (i + 1) as u64, &keypair);
        store_a.append_chio_receipt_returning_seq(&receipt)?;
    }
    store_a.flush_receipt_writes()?;

    // A stale baseline flush: no checkpoint exists yet.
    let baseline = store_a.flush_receipt_writes()?;
    assert_eq!(baseline.latest_checkpoint_seq, None);
    assert_eq!(baseline.uncheckpointed_end_seq, Some(3));

    // A second handle on the SAME DB extends the checkpoint chain.
    let store_b = SqliteReceiptStore::open_existing(&path)?;
    store_b.create_next_receipt_checkpoint(3, &keypair)?;

    // store_a had no intervening write, so its head atomics are stale. The
    // flush report must still reflect the externally persisted checkpoint.
    let report = store_a.flush_receipt_writes()?;
    assert_eq!(
        report.latest_checkpoint_seq,
        Some(1),
        "flush must reflect the externally extended checkpoint"
    );
    assert_eq!(report.latest_checkpointed_entry_seq, 3);
    assert_eq!(report.uncheckpointed_start_seq, None);
    assert_eq!(report.uncheckpointed_end_seq, None);

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 2, finding 1: on a shared receipt DB another writer can commit a
/// due checkpoint AFTER this actor's append pre-check but BEFORE its batch tx.
/// The batch adopts that writer's claim-log rows via the baseline delta yet
/// leaves `head.latest_checkpoint` stale, so building from the stale position
/// would try to rebuild the already-committed checkpoint with THIS actor's own
/// issued_at (clock skew) -> "already exists with different content", recording
/// writer.last_error and reporting the store UNHEALTHY even though the persisted
/// chain is valid (the idempotent-identical guard does not cover this skew
/// case). The fix refreshes the head against the latest persisted checkpoint
/// before building, ADOPTING the external checkpoint instead of rebuilding it.
#[test]
fn shared_db_background_build_adopts_external_checkpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-bg-adopt-external");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-adopt-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // "Instance B" (another writer on the same file) commits the due checkpoint
    // 1 (batch 1..=3). The store enforces checkpoint-key == receipt-signer-key,
    // so it is signed by the same kernel key but carries a DISTINCT issued_at
    // (the clock-skew case): byte-different from the checkpoint "instance A"
    // would build for the same range.
    let receipt_bytes = canonical_receipt_bytes(&store, 1, max_batch);
    let mut external = build_checkpoint(1, 1, max_batch, &receipt_bytes, &keypair)?;
    external.body.issued_at = external.body.issued_at.saturating_add(1_000);
    let body_bytes = canonical_json_bytes(&external.body).test_unwrap();
    external.signature = keypair.sign(&body_bytes);
    store.store_checkpoint(&external)?;

    // "Instance A" holds a STALE head: its pre-check ran before B committed, so
    // it still believes the chain is empty (latest_checkpoint = None) while its
    // claim-log counters already cover entries 1..=3 (adopted via the baseline
    // delta). Building due checkpoints from this stale head drives the exact
    // production path. (The reader pool is used only as a connection source for
    // this off-thread reproduction; the fix lives in build_due_checkpoints.)
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: max_batch,
        claim_log_max_seq: max_batch,
    };
    let signer_a = signer(&keypair, max_batch);
    let result = build_due_checkpoints(&store.pool, &mut stale_head, &signer_a);
    assert!(
        result.is_ok(),
        "stale-head background build must adopt the external checkpoint, got {result:?}"
    );
    assert_eq!(
        stale_head.checkpoint_seq(),
        1,
        "the head must have adopted the externally committed checkpoint"
    );
    assert!(
        store.load_checkpoint_by_seq(2)?.is_none(),
        "the already-covered range must not be rebuilt into a second checkpoint"
    );
    // The persisted chain is unchanged and audits clean.
    let status = store.receipt_checkpoint_status(Some(max_batch))?;
    assert!(status.healthy, "chain must stay healthy: {status:?}");
    assert_eq!(status.latest_checkpoint_seq, Some(1));

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 2, finding 2: a prior background checkpoint build that failed set
/// writer.last_error. A later SUCCESSFUL build reached via a writer-routed op
/// (a `Write` job crossing the threshold) refreshes the head snapshot but, on
/// the append batch's clearing path being skipped, must ALSO clear last_error so
/// receipt_store_health reflects the recovered state instead of staying
/// unhealthy until the next normal append.
#[test]
fn successful_checkpoint_build_clears_stale_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-clear-stale-error");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-clear-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // A due checkpoint (1..=3) is pending; none built yet.
    assert!(store.load_checkpoint_by_seq(1)?.is_none());

    // Simulate a writer that recorded a PRIOR background-checkpoint failure
    // (e.g. a transient build panic) that set last_error and was never cleared
    // by a subsequent append batch.
    let health = ReceiptCommitWriterHealth::default();
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = Some("prior background checkpoint build failed".to_string());
    }

    // The recovery build succeeds and must clear the stale error.
    let mut head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: max_batch,
        claim_log_max_seq: max_batch,
    };
    build_due_checkpoints_and_record(
        &store.pool,
        &mut head,
        &Some(signer(&keypair, max_batch)),
        &health,
    );
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "the recovery build must persist checkpoint 1"
    );
    let cleared = health
        .last_error
        .lock()
        .map(|guard| guard.is_none())
        .unwrap_or(false);
    assert!(
        cleared,
        "a successful background build must clear the stale writer error"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 2, finding 4: flush_report reads the persisted latest
/// checkpoint's batch_end_seq to reflect an externally extended chain. It must
/// only trust that row if its signed body VERIFIES; a tampered/out-of-band row
/// with an inflated batch_end_seq must not make the report advertise a false
/// checkpointed_entry_seq and hide the uncheckpointed range. A VALID external
/// checkpoint is still reflected (F5 preserved).
#[test]
fn flush_report_ignores_unverified_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-flush-ignore-forged-ckpt");
    let keypair = receipt_test_keypair();
    let store_a = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-forge-{i}"), (i + 1) as u64, &keypair);
        store_a.append_chio_receipt_returning_seq(&receipt)?;
    }
    store_a.flush_receipt_writes()?;

    // A VALID external checkpoint (built by a second handle) is still reflected.
    let store_b = SqliteReceiptStore::open_existing(&path)?;
    store_b.create_next_receipt_checkpoint(3, &keypair)?;
    let good = store_a.flush_receipt_writes()?;
    assert_eq!(good.latest_checkpoint_seq, Some(1));
    assert_eq!(good.latest_checkpointed_entry_seq, 3);

    // Forge the latest checkpoint row: inflate the batch_end_seq COLUMN while
    // leaving the signed body untouched, so the column no longer matches the
    // signed body (same tamper mechanics as the verified_head fixtures).
    let connection = store_a.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET batch_end_seq = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![9_999_i64],
    )?;
    drop(connection);

    // flush_report must NOT trust the forged, unverified row: it falls back to
    // the actor's verified head (which never saw a checkpoint), so the bogus
    // inflated batch_end_seq is not reported and the uncheckpointed range is
    // restored.
    let report = store_a.flush_receipt_writes()?;
    assert_ne!(
        report.latest_checkpointed_entry_seq, 9_999,
        "a forged checkpoint row must not be reported as checkpointed progress"
    );
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.uncheckpointed_end_seq, Some(3));

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 2, finding 5: the OPERATOR/IMPORT checkpoint append
/// (store_checkpoint -> store_kernel_checkpoint_atomic) only parses the LATEST
/// checkpoint as predecessor, so a mid-chain tamper whose latest row still
/// parses would let an operator extend an already-corrupt chain. The operator
/// path must re-verify the full chain and fail closed. (This does NOT touch the
/// RFC-0006 background builder, which stays on the incremental head, F22.)
#[test]
fn operator_checkpoint_append_reverifies_chain() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-operator-reverify-chain");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-op-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Two checkpoints: 1 (1..=2), 2 (3..=4).
    store.create_next_receipt_checkpoint(2, &keypair)?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    // Two more uncheckpointed entries so a VALID checkpoint 3 (5..=6) exists.
    for i in 4..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-op-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let checkpoint_two = store
        .load_checkpoint_by_seq(2)?
        .ok_or("checkpoint 2 must exist")?;
    let range_bytes = canonical_receipt_bytes(&store, 5, 6);
    let checkpoint_three =
        build_checkpoint_with_previous(3, 5, 6, &range_bytes, &keypair, Some(&checkpoint_two))?;

    // Tamper an EARLIER checkpoint (seq 1) while the LATEST (seq 2) still parses:
    // mutate checkpoint 1's signed batch_end_seq so it no longer matches its
    // stored column. The incremental predecessor check (which only looks at the
    // latest) would miss this.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":2', '\"batch_end_seq\":1') WHERE checkpoint_seq = 1",
        [],
    )?;
    drop(connection);

    // The operator append must fail closed: the full chain re-verification
    // catches the mid-chain tamper before extending the chain.
    let error = store
        .store_checkpoint(&checkpoint_three)
        .err()
        .ok_or("operator checkpoint append must fail closed on a mid-chain tamper")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict, got {error:?}"
    );
    assert!(
        store.load_checkpoint_by_seq(3)?.is_none(),
        "the corrupt chain must not be extended with checkpoint 3"
    );

    let _ = fs::remove_file(path);
    Ok(())
}
