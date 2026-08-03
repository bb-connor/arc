use super::super::*;
use super::support::*;
use chio_kernel::ReceiptStore;

#[test]
fn graceful_close_drains_the_writer_before_private_directory_cleanup(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_fs::private_tempdir("receipt-close-")?;
    let path = directory.path().join("receipts.sqlite3");
    let store = SqliteReceiptStore::open(&path)?;
    let writer_health = std::sync::Arc::clone(&store.receipt_commit_actor.health);

    let receipt = sample_receipt_with_id("rcpt-graceful-close");
    assert_eq!(store.append_chio_receipt_returning_seq(&receipt)?, 1);
    let alongside = crate::SqliteIouEnvelopeStore::open_alongside(&store)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let late_writer = store.writer_handle();

    let report = store.close()?;
    let late_write = late_writer.run_write(|_connection| Ok(()));
    assert!(
        matches!(
            late_write,
            Err(ReceiptStoreError::Pool(ref message)) if message.contains("actor is closing")
        ),
        "a co-located handle retained across close must reject later writes: {late_write:?}"
    );
    drop(alongside);
    drop(late_writer);
    assert_eq!(report.latest_committed_entry_seq, 1);
    assert_eq!(
        writer_health
            .queue_depth
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        writer_health
            .inflight
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    directory.close()?;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn close_revokes_idle_bound_connections_and_releases_their_handles(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_fs::private_tempdir("receipt-bound-close-")?;
    let path = directory.path().join("receipts.sqlite3");
    let store = SqliteReceiptStore::open(&path)?;
    let bound = store.open_bound_colocated_connection()?;
    let identity = {
        let inner = bound
            .state
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("bound connection lock is poisoned"))?;
        let live = inner
            .as_ref()
            .ok_or("bound connection must be live before close")?;
        std::sync::Arc::downgrade(&live.database_identity_file)
    };

    let report = store.close()?;
    assert_eq!(report.latest_committed_entry_seq, 0);
    let error = bound
        .validated_connection()
        .err()
        .ok_or("a bound connection retained across close must be revoked")?;
    assert!(
        error.to_string().contains("revoked by store close"),
        "unexpected post-close bound connection error: {error}"
    );
    let inner = bound
        .state
        .inner
        .lock()
        .map_err(|_| std::io::Error::other("bound connection lock is poisoned"))?;
    assert!(inner.is_none(), "close must remove the revocable inner");
    drop(inner);
    assert!(
        identity.upgrade().is_none(),
        "close must drop the retained database and parent descriptors"
    );

    // Keep the public wrapper alive while removing the directory. It now owns
    // only an empty revocation state.
    directory.close()?;
    assert!(!path.exists());
    drop(bound);
    Ok(())
}

#[test]
fn close_fails_without_waiting_for_an_active_bound_connection_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_fs::private_tempdir("receipt-bound-active-")?;
    let path = directory.path().join("receipts.sqlite3");
    let store = SqliteReceiptStore::open(&path)?;
    let bound = store.open_bound_colocated_connection()?;
    let active_guard = bound.validated_connection()?;
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let closer = std::thread::spawn(move || {
        let _ = result_tx.send(store.close());
    });

    let close_result = match result_rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(result) => result,
        Err(error) => {
            drop(active_guard);
            drop(bound);
            let _ = closer.join();
            return Err(std::io::Error::other(format!(
                "close waited for an active bound connection guard: {error}"
            ))
            .into());
        }
    };
    closer
        .join()
        .map_err(|_| std::io::Error::other("receipt close thread panicked"))?;
    let error = close_result
        .err()
        .ok_or("close must fail while a bound connection operation is active")?;
    assert!(
        error.to_string().contains("active_operations=1"),
        "unexpected active bound connection error: {error}"
    );
    let post_close_error = bound
        .validated_connection()
        .err()
        .ok_or("new bound operations must be rejected after failed close")?;
    assert!(post_close_error
        .to_string()
        .contains("revoked by store close"));

    drop(active_guard);
    drop(bound);
    directory.close()?;
    Ok(())
}

#[test]
fn close_revokes_direct_writes_before_publishing_the_final_actor_barrier(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_fs::private_tempdir("receipt-close-order-")?;
    let path = directory.path().join("receipts.sqlite3");
    let store = SqliteReceiptStore::open(&path)?;
    let bound = store.open_bound_colocated_connection()?;
    let handle = store.writer_handle();
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker = std::thread::spawn(move || {
        handle.run_write(move |_connection| -> Result<(), ReceiptStoreError> {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
    });
    started_rx.recv()?;

    let close_job = std::thread::spawn(move || store.close());
    let revoke_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !bound.state.revoked.load(Ordering::SeqCst) && std::time::Instant::now() < revoke_deadline
    {
        std::thread::yield_now();
    }
    if !bound.state.revoked.load(Ordering::SeqCst) {
        let _ = release_tx.send(());
        let _ = blocker.join();
        let _ = close_job.join();
        return Err("close did not revoke direct writers before its actor barrier".into());
    }

    let error = bound
        .validated_connection()
        .err()
        .ok_or("a direct write started after close established revocation")?;
    assert!(error.to_string().contains("revoked by store close"));

    release_tx.send(())?;
    blocker
        .join()
        .map_err(|_| "blocking writer thread panicked")??;
    let report = close_job
        .join()
        .map_err(|_| "receipt close thread panicked")??;
    assert_eq!(report.latest_committed_entry_seq, 0);

    directory.close()?;
    drop(bound);
    Ok(())
}

/// A panic inside a Write-routed job (one of
/// the ~30 rerouted write families: lineage, liability, underwriting,
/// reconciliation, capability, federated, IOU, checkpoint, reseed) must not
/// take down the single writer thread for the rest of the process lifetime.
///
/// Two assertions:
///   (a) the panicking job's own caller gets a typed `Err`, not a hang;
///   (b) a SUBSEQUENT normal append on the SAME store still succeeds. This
///       is the teeth: without `catch_unwind` isolating the job, the writer
///       thread is dead here and every later append/write/flush observes
///       `Disconnected` -> `receipt_actor_unavailable_error()` forever (or,
///       if the caller happened to be blocked on `recv()` at the moment the
///       thread died mid-response, a hang).
#[test]
fn writer_job_panic_does_not_kill_the_actor() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-job-panic");
    let store = SqliteReceiptStore::open(&path)?;

    let panic_result =
        store
            .writer_handle()
            .run_write(|_connection| -> Result<(), ReceiptStoreError> {
                panic!("injected test panic in writer job")
            });
    let error = match panic_result {
        Ok(()) => return Err("expected the panicking job to return Err, got Ok".into()),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("receipt writer job panicked"),
        "unexpected error message: {message}"
    );

    // Teeth: the writer thread survived. A normal Write-routed job still
    // reaches the (same) actor thread and completes.
    let _thread_id = store
        .writer_handle()
        .run_write(|_connection| Ok(std::thread::current().id()))?;

    // Teeth: a normal append still commits durably.
    let receipt = sample_receipt_with_id("rcpt-after-writer-job-panic");
    let seq = store.append_chio_receipt_returning_seq(&receipt)?;
    assert_eq!(
        seq, 1,
        "append after a caught writer-job panic must still commit"
    );

    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert_eq!(
        health.writer.inflight, 0,
        "inflight must drain to zero across the panicking job and the two jobs after it"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// A panic inside `commit_receipt_batch` (the append path itself, not a
/// Write-routed job) is at least as serious as the store-wide append faults
/// that path already poisons on: the writer's durable position is now
/// unverifiable, so the head is poisoned and the pre-dispatch gate fails closed.
/// The writer thread itself survives (the panic is caught), so an operator
/// reseed recovers the store. Uses the `test_hooks::PANIC_DURING_APPEND_BATCH`
/// fault hook, which fires inside the per-request insert loop before the
/// interrupted request's transaction commits and before any response is sent,
/// exercising the `fan_out_batch_panic_error` path (the pre-cloned response
/// senders, not the normal `receipt_batch_error_results` fan-out).
///
/// This crate's tests run in parallel and the fault-hook flag is process-global,
/// so the hook is additionally gated on
/// `PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH`: only a request carrying that
/// exact `content_hash` can panic (not `receipt.id` -- `ChioReceipt::sign`
/// always overwrites `id` with a content-derived hash, so a caller-chosen id
/// string does not survive signing), so a concurrently running, unrelated append
/// test cannot be hit by this test's injected panic.
#[test]
fn append_batch_panic_poisons_the_head_and_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-append-batch-panic");
    let store = SqliteReceiptStore::open(&path)?;

    test_hooks::PANIC_DURING_APPEND_BATCH.store(true, std::sync::atomic::Ordering::SeqCst);
    let receipt = sample_receipt_with_id(test_hooks::PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID);
    let panic_result = store.append_chio_receipt_returning_seq(&receipt);
    test_hooks::PANIC_DURING_APPEND_BATCH.store(false, std::sync::atomic::Ordering::SeqCst);

    let error = match panic_result {
        Ok(seq) => {
            return Err(
                format!("expected the panicking append to return Err, got seq {seq}").into(),
            )
        }
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("receipt writer job panicked"),
        "unexpected error message: {error}"
    );
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "unwinding an append batch must drop every command lease exactly once"
    );
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .queue_depth
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the panicking batch was already dequeued"
    );

    // Teeth: the caught panic poisoned the head, so the pre-dispatch gate reports
    // the writer is no longer serving and denies before another tool runs.
    assert!(
        store.writer_serving_closed(),
        "a caught append-batch panic must trip the serving-closed gate"
    );

    // The writer THREAD survived the caught panic (a dead thread would answer
    // Disconnected): the next append is rejected with the recoverable
    // poisoned-head Conflict, not an actor-unavailable error.
    match store
        .append_chio_receipt_returning_seq(&sample_receipt_with_id("rcpt-after-append-panic"))
    {
        Ok(seq) => {
            return Err(format!(
                "expected the poisoned head to reject the next append, got seq {seq}"
            )
            .into())
        }
        Err(rejected) => assert!(
            rejected
                .to_string()
                .contains("verified head is unavailable"),
            "expected a poisoned-head rejection, got: {rejected}"
        ),
    }

    // An operator reseed clears the poison; the interrupted append's transaction
    // rolled back cleanly, so the store resumes serving at seq 1.
    store.reseed_verified_head()?;
    assert!(
        !store.writer_serving_closed(),
        "reseed must clear the poisoned head"
    );
    let seq = store.append_chio_receipt_returning_seq(&sample_receipt_with_id(
        "rcpt-after-append-recovered",
    ))?;
    assert_eq!(
        seq, 1,
        "the panicking append's tx must have rolled back cleanly, leaving seq 1 free"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// {Append, Write, Flush} from many threads: every Write closure executes on
/// exactly one thread (single-writer serialization), all appends commit, and
/// inflight accounting drains to zero (no lost pre-send increments).
#[test]
fn writer_commands_serialize_and_never_lose_inflight_accounting(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-single-writer-stress");
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);

    // `std::thread::ThreadId` implements `Hash + Eq` but not `Ord`, so a
    // `HashSet` (not `BTreeSet`) tracks the distinct writer thread here.
    let writer_threads: std::sync::Arc<Mutex<std::collections::HashSet<std::thread::ThreadId>>> =
        std::sync::Arc::new(Mutex::new(std::collections::HashSet::new()));
    let mut handles = Vec::new();

    for worker in 0..4u32 {
        let store = std::sync::Arc::clone(&store);
        let writer_threads = std::sync::Arc::clone(&writer_threads);
        handles.push(thread::spawn(move || -> Result<(), String> {
            for i in 0..25u32 {
                match i % 3 {
                    0 => {
                        let receipt = sample_receipt_with_id(&format!("rcpt-stress-{worker}-{i}"));
                        ReceiptStore::append_chio_receipt_returning_seq(store.as_ref(), &receipt)
                            .map_err(|error| error.to_string())?;
                    }
                    1 => {
                        let observed = store
                            .writer_handle()
                            .run_write(|_connection| Ok(std::thread::current().id()))
                            .map_err(|error| error.to_string())?;
                        writer_threads
                            .lock()
                            .map_err(|_| "writer thread set poisoned".to_string())?
                            .insert(observed);
                    }
                    _ => {
                        store
                            .flush_receipt_writes()
                            .map_err(|error| error.to_string())?;
                    }
                }
            }
            Ok(())
        }));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| "stress worker panicked")?
            .map_err(std::io::Error::other)?;
    }

    // Single-writer serialization: every Write job ran on one thread.
    let distinct = writer_threads
        .lock()
        .map_err(|_| "writer thread set poisoned")?
        .len();
    assert_eq!(
        distinct, 1,
        "expected exactly one writer thread, got {distinct}"
    );

    // Quiesce, then check the books: nothing in flight, all appends counted.
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert_eq!(health.writer.inflight, 0, "inflight must drain to zero");
    // committed_total reconciles BOTH commit paths: the Append path (i % 3 == 0
    // on 9 of 25 iterations per worker) AND the writer-routed `run_write` path
    // (i % 3 == 1 on 8 of 25 iterations per worker), whose successful outcome is
    // folded into committed_total. Flushes (i % 3 == 2) are not commits.
    assert_eq!(health.writer.committed_total, 4 * 9 + 4 * 8);
    assert_eq!(health.writer.failed_total, 0);
    // Only the Append path inserts claim-log entries; the run_write closures
    // return a thread id without writing, so the log length tracks appends only.
    assert_eq!(health.latest_committed_entry_seq, 4 * 9);

    let _ = fs::remove_file(path);
    Ok(())
}

/// Force every pooled reader connection into `PRAGMA query_only = ON`, then
/// exercise the routed write surface: all writes must still succeed (they run
/// on the writer connection), while a direct write through the reader pool
/// must fail. r2d2 creates connections lazily up to max_size, so grabbing all
/// DEFAULT_READER_POOL_MAX_SIZE connections at once pins the whole pool.
#[test]
fn reader_pool_never_begins_a_write_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-reader-pool-readonly");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    {
        let mut held = Vec::new();
        for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
            held.push(store.connection()?);
        }
        for connection in &held {
            connection.execute_batch("PRAGMA query_only = ON;")?;
        }
    }

    // Control: the reader pool now refuses writes.
    {
        let connection = store.connection()?;
        let denied = connection.execute("CREATE TABLE reader_probe (x INTEGER)", []);
        assert!(denied.is_err(), "reader pool accepted a write");
    }

    // The routed write surface still works end to end.
    let receipt = sample_receipt_with_keypair("rcpt-ro-pool-0", 1, &keypair);
    ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?.ok_or("expected seq")?;
    let child = sample_child_receipt_with_keypair_and_timestamp("child-ro-pool-0", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    store.record_session_anchor_record(
        "sess-ro",
        "anchor-ro",
        "fp-ro",
        3,
        None,
        &serde_json::json!({"anchor": "ro"}),
    )?;
    // `record_request_lineage_record` validates `lineage_json` against
    // `chio_core::session::RequestLineageRecord` (requires a `schema` field
    // among others), unlike `record_session_anchor_record`'s unvalidated
    // passthrough JSON above; `request_lineage_json` builds a
    // schema-compliant payload.
    store.record_request_lineage_record(
        "sess-ro",
        "req-ro",
        None,
        Some("anchor-ro"),
        4,
        None,
        &request_lineage_json("req-ro", "anchor-ro", None),
    )?;
    let _links = store.list_receipt_lineage_statement_links("rcpt-ro-pool-0")?;
    let _verification = store.receipt_lineage_verification("rcpt-ro-pool-0")?;
    store.create_next_receipt_checkpoint(2, &keypair)?;

    let iou_store = crate::SqliteIouEnvelopeStore::open_alongside(&store)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    drop(iou_store); // migration DDL ran on the writer; construction succeeding is the assertion

    let _ = fs::remove_file(path);
    Ok(())
}
