//! Dispatch-intent journal tests: schema creation, durable insert/consume,
//! boot reconciliation, and the health surface.

use crate::SqliteReceiptStore;

use super::support::unique_db_path;

fn sample_intent(request_id: &str) -> chio_kernel::receipt_store::DispatchIntentRecord {
    use chio_kernel::receipt_store::{DispatchIntentRecord, SideEffectClass};
    DispatchIntentRecord {
        request_id: request_id.to_string(),
        capability_id: "cap-abc".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "write_file".to_string(),
        parameter_hash: "ph-123".to_string(),
        side_effect_class: SideEffectClass::SideEffecting,
        monetary: false,
        rail: None,
        rail_authorization_id: None,
        tenant_id: None,
        created_at_unix_ms: 42,
    }
}

fn open_intent_row_count(store: &SqliteReceiptStore) -> Result<i64, Box<dyn std::error::Error>> {
    let connection = store.reader_connection_for_test()?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'open'",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

#[test]
fn record_dispatch_intent_inserts_and_rejects_duplicate() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-intents-insert");
    let store = SqliteReceiptStore::open(&path)?;

    store.record_dispatch_intent(&sample_intent("req-A"))?;
    assert_eq!(open_intent_row_count(&store)?, 1);

    // A second write reusing the request id is rejected fail-closed rather
    // than duplicating an effect record.
    let duplicate = store.record_dispatch_intent(&sample_intent("req-A"));
    let message = duplicate
        .err()
        .ok_or("expected duplicate request_id to be rejected")?
        .to_string();
    assert!(
        message.contains("dispatch intent"),
        "unexpected error: {message}"
    );
    assert_eq!(open_intent_row_count(&store)?, 1);

    // The bounded variant commits durably within budget on a live writer.
    store.record_dispatch_intent_with_timeout(
        &sample_intent("req-B"),
        std::time::Duration::from_secs(5),
    )?;
    assert_eq!(open_intent_row_count(&store)?, 2);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn attach_rail_ref_updates_open_intent_and_notfound_when_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-attach");
    let store = SqliteReceiptStore::open(&path)?;
    store.record_dispatch_intent(&sample_intent("req-M"))?;

    store.attach_dispatch_intent_rail_ref("req-M", "auth-xyz")?;
    let connection = store.reader_connection_for_test()?;
    let attached: String = connection.query_row(
        "SELECT rail_authorization_id FROM chio_dispatch_intents WHERE request_id = 'req-M'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(attached, "auth-xyz");

    // Attaching to a non-existent intent reports NotFound; the best-effort
    // caller logs and continues.
    let missing = store.attach_dispatch_intent_rail_ref("req-absent", "auth-1");
    assert!(missing.is_err());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn consume_intent_removes_row_and_persists_receipt_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::receipt_store::{DispatchIntentKey, ReceiptStore};

    let path = unique_db_path("chio-intents-consume");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = super::support::sample_receipt_with_keypair("consume-ok", 1, &keypair);
    let mut intent = sample_intent("req-C");
    intent.capability_id = receipt.capability_id.clone();
    intent.tool_server = receipt.tool_server.clone();
    intent.tool_name = receipt.tool_name.clone();
    intent.parameter_hash = receipt.action.parameter_hash.clone();
    intent.tenant_id = receipt.tenant_id.clone();
    store.record_dispatch_intent(&intent)?;

    let key = DispatchIntentKey {
        request_id: "req-C".to_string(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        tenant_id: receipt.tenant_id.clone(),
    };
    let seq = store.append_chio_receipt_consuming_intent(&receipt, &key)?;
    assert!(seq.is_some(), "receipt persisted, returns its entry seq");
    store.flush_receipt_writes()?;

    // Intent gone, receipt present: the two shared one commit.
    assert_eq!(open_intent_row_count(&store)?, 0);
    assert!(store.load_chio_receipt(&receipt.id)?.is_some());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn consume_intent_parameter_hash_mismatch_aborts_and_keeps_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::receipt_store::{DispatchIntentKey, ReceiptStore};

    let path = unique_db_path("chio-intents-consume-mismatch");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = super::support::sample_receipt_with_keypair("consume-bad", 1, &keypair);

    // A key whose parameter_hash disagrees with the receipt is rejected before
    // any write reaches the transaction.
    let mut intent = sample_intent("req-X");
    intent.parameter_hash = receipt.action.parameter_hash.clone();
    intent.tenant_id = receipt.tenant_id.clone();
    store.record_dispatch_intent(&intent)?;
    let disagreeing_key = DispatchIntentKey {
        request_id: "req-X".to_string(),
        parameter_hash: "wrong-hash".to_string(),
        tenant_id: receipt.tenant_id.clone(),
    };
    assert!(store
        .append_chio_receipt_consuming_intent(&receipt, &disagreeing_key)
        .is_err());

    // A key that matches the receipt but not the STORED intent row (the intent
    // was journaled for different parameters) must abort the whole
    // transaction: the receipt must not persist and the intent must stay open.
    let mut stale_intent = sample_intent("req-Y");
    stale_intent.parameter_hash = "journaled-for-other-parameters".to_string();
    store.record_dispatch_intent(&stale_intent)?;
    let key_for_y = DispatchIntentKey {
        request_id: "req-Y".to_string(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        tenant_id: receipt.tenant_id.clone(),
    };
    let result = store.append_chio_receipt_consuming_intent(&receipt, &key_for_y);
    assert!(result.is_err(), "stored-intent mismatch must abort");
    store.flush_receipt_writes()?;

    assert_eq!(
        open_intent_row_count(&store)?,
        2,
        "both intents remain open after the aborted consumes"
    );
    assert!(
        store.load_chio_receipt(&receipt.id)?.is_none(),
        "receipt must not persist when the consume aborts"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn timed_out_intent_write_does_not_land_after_the_writer_drains(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-timeout-abandon");
    let store = SqliteReceiptStore::open(&path)?;

    // Occupy the single writer with a job that parks until released, so the
    // bounded intent write below times out while its own job is still queued
    // behind it.
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let error = store.record_dispatch_intent_with_timeout(
        &sample_intent("req-timeout-abandon"),
        std::time::Duration::from_millis(100),
    );
    assert!(
        matches!(
            error,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "the bounded intent write must fail closed on a stalled writer"
    );

    // Unblock the writer and drain the queue past the abandoned job.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;

    // The caller already denied before dispatch, so the queued insert must
    // not land afterwards: a row here would dead-letter at the next boot as
    // a false orphan for a call that never executed.
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a timed-out intent write must not land after the caller denied"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn timeout_deny_returns_within_one_budget_on_a_stalled_writer(
) -> Result<(), Box<dyn std::error::Error>> {
    // The bounded intent write exists to cap the pre-dispatch wall-clock: a
    // stalled writer must fail the caller closed after ONE budget. The
    // compensating sweep enqueued on timeout needs no answer before the
    // caller denies (FIFO order already runs it after the insert), so it
    // must not spend a second budget waiting on the same stalled writer.
    let path = unique_db_path("chio-intents-timeout-budget");
    let store = SqliteReceiptStore::open(&path)?;

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let budget = std::time::Duration::from_millis(500);
    let started = std::time::Instant::now();
    let error = store.record_dispatch_intent_with_timeout(&sample_intent("req-budget"), budget);
    let elapsed = started.elapsed();
    assert!(
        matches!(
            error,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "the bounded intent write must fail closed on a stalled writer"
    );
    assert!(
        elapsed < budget + std::time::Duration::from_millis(400),
        "the timeout deny must not stack a second sweep wait on top of the \
         insert's budget; elapsed {elapsed:?} for budget {budget:?}"
    );

    // The detached sweep still drains with the writer: no stale row survives.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "the sweep must still run behind the insert after the writer drains"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn straddling_intent_commit_is_cleared_after_a_timeout_deny(
) -> Result<(), Box<dyn std::error::Error>> {
    // A slow-but-successful insert can pass its final abandoned check and be
    // inside its commit when the caller's deadline expires: the abandoned
    // marker can no longer stop the row from landing, the caller reports a
    // timeout, and the evaluator denies before dispatch. The landed row must
    // then be swept by the job the timeout path enqueues behind the insert
    // on the single writer; otherwise it would dead-letter at the next boot
    // as a false orphan for a call that never executed. The instant between
    // the deadline expiring and the marker landing cannot be held open from
    // outside, so this drives the production job pair through the writer
    // with the shared slots staged exactly as that race leaves them.
    let path = unique_db_path("chio-intents-straddle-clear");
    let store = SqliteReceiptStore::open(&path)?;

    let intent = sample_intent("req-straddle-clear");
    let abandoned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let landed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let insert = super::super::support::dispatch_intent_insert_job_unless_abandoned(
        &intent,
        std::sync::Arc::clone(&abandoned),
        std::sync::Arc::clone(&landed),
    );
    // The final abandoned check races ahead of the marker and the commit
    // lands: the caller's own insert is durable even though the caller is
    // about to observe a timeout.
    store.writer_handle().run_write(insert)?;
    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "the straddling insert must be durable before the caller times out"
    );
    // Only now does the deadline fire: too late for the marker to stop the
    // commit, which already recorded itself in the shared slot.
    abandoned.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        landed.load(std::sync::atomic::Ordering::SeqCst),
        "a commit that outruns the marker must record itself as landed"
    );

    // The sweep the timeout path enqueues behind the insert reads the slot
    // and deletes exactly the row this attempt created.
    let key = chio_kernel::receipt_store::DispatchIntentKey {
        request_id: intent.request_id.clone(),
        parameter_hash: intent.parameter_hash.clone(),
        tenant_id: intent.tenant_id.clone(),
    };
    store
        .writer_handle()
        .run_write(super::super::support::dispatch_intent_sweep_landed_job(
            &key, landed,
        ))?;

    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a landed intent row must not survive a timeout deny as a false orphan"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn duplicate_timeout_does_not_clear_the_preexisting_open_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // A retry (or concurrent duplicate) of a request that already has an
    // open intent can time out on a slow writer. Its queued insert then
    // refuses (abandoned marker, or the primary key it collides with), so
    // the compensating sweep behind it has nothing of its own to delete:
    // removing the first invocation's row would erase that call's durable
    // crash marker and reject its terminal receipt's consume.
    let path = unique_db_path("chio-intents-duplicate-timeout");
    let store = SqliteReceiptStore::open(&path)?;

    // The first invocation's intent is durably open; its call is in flight.
    let intent = sample_intent("req-duplicate-timeout");
    store.record_dispatch_intent(&intent)?;
    assert_eq!(open_intent_row_count(&store)?, 1);

    // Park the writer so the duplicate attempt's bounded wait expires while
    // its insert (and the sweep behind it) are still queued.
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let error =
        store.record_dispatch_intent_with_timeout(&intent, std::time::Duration::from_millis(100));
    assert!(
        matches!(
            error,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "the duplicate attempt must still fail closed on expiry"
    );

    // Drain the queue past the refused insert and the sweep behind it.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;

    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "the first invocation's open intent must survive a duplicate's timeout"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

struct RecordingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for RecordingReconciler {
    fn resolve(
        &self,
        intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        // Default posture: dead-letter every orphan; a monetary orphan records
        // its rail so an operator can reconcile against the rail.
        let detail = match (&intent.rail, &intent.rail_authorization_id) {
            (Some(rail), Some(auth)) => {
                format!("outcome unknown; rail={rail}; rail_authorization_id={auth}")
            }
            (Some(rail), None) => format!("outcome unknown; rail={rail}"),
            _ => "outcome unknown".to_string(),
        };
        Ok(chio_kernel::receipt_store::DispatchIntentResolution::DeadLetter { detail })
    }
}

#[test]
fn reconcile_dead_letters_orphans_and_reports_counts() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-reconcile");
    let store = SqliteReceiptStore::open(&path)?;

    // A clean run: no open intents means nothing to reconcile.
    let clean = store.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(clean.open, 0);
    assert_eq!(clean.dead_lettered, 0);

    // Two orphans: one side-effecting, one monetary with a rail attached.
    store.record_dispatch_intent(&sample_intent("orphan-se"))?;
    let mut monetary = sample_intent("orphan-mon");
    monetary.side_effect_class = chio_kernel::receipt_store::SideEffectClass::Monetary;
    monetary.monetary = true;
    monetary.rail = Some("x402".to_string());
    monetary.rail_authorization_id = Some("auth-9".to_string());
    store.record_dispatch_intent(&monetary)?;

    let report = store.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.open, 2);
    assert_eq!(report.dead_lettered, 2);

    // Both are now dead_letter; the monetary detail names the rail reference.
    let connection = store.reader_connection_for_test()?;
    let dead: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'dead_letter'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(dead, 2);
    let detail: String = connection.query_row(
        "SELECT resolution_detail FROM chio_dispatch_intents WHERE request_id = 'orphan-mon'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        detail.contains("x402") && detail.contains("auth-9"),
        "monetary detail names the rail reference: {detail}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn attach_defers_reconciliation_while_a_sibling_writer_is_live(
) -> Result<(), Box<dyn std::error::Error>> {
    // The store supports sibling writer instances on one database file. An
    // open intent then proves only that ITS writer has not consumed it yet:
    // while that writer is alive the call may still be in flight, and
    // claiming the row as a restart orphan would erase a live crash marker,
    // reject the owner's terminal receipt, and flip health for work that is
    // not an incident. Reconciliation must claim open rows only when this
    // instance holds the file exclusively.
    let path = unique_db_path("chio-intents-live-sibling");
    let owner = SqliteReceiptStore::open(&path)?;
    owner.record_dispatch_intent(&sample_intent("req-live-sibling"))?;

    // A second instance attaching to the shared file observes the owner's
    // in-flight intent but must leave it to its owner.
    let sibling = SqliteReceiptStore::open(&path)?;
    let report = sibling.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(
        report.dead_lettered, 0,
        "a live sibling's open intent must not dead-letter"
    );
    assert_eq!(
        report.deferred_to_live_writer, 1,
        "the deferral must be reported, never silent"
    );
    assert_eq!(
        open_intent_row_count(&sibling)?,
        1,
        "the owner's crash marker must survive the sibling's attach"
    );

    // Once both instances are gone the same row is a true restart orphan: a
    // fresh attach holds the file exclusively and still reconciles it.
    drop(owner);
    drop(sibling);
    let restarted = SqliteReceiptStore::open(&path)?;
    let report = restarted.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        report.dead_lettered, 1,
        "a true restart must still dead-letter its orphans"
    );
    assert_eq!(report.deferred_to_live_writer, 0);
    assert_eq!(open_intent_row_count(&restarted)?, 0);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Rail-aware reconciler: proves the outcome of monetary orphans against the
/// rail and dead-letters everything else.
struct RailProvingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for RailProvingReconciler {
    fn resolve(
        &self,
        intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        if intent.monetary {
            Ok(
                chio_kernel::receipt_store::DispatchIntentResolution::MonetaryReconciled {
                    rail_reference: "tx-123".to_string(),
                },
            )
        } else {
            Ok(
                chio_kernel::receipt_store::DispatchIntentResolution::DeadLetter {
                    detail: "outcome unknown".to_string(),
                },
            )
        }
    }
}

#[test]
fn monetary_reconciled_intent_is_not_a_dead_letter_and_health_stays_green(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-monetary-reconciled");
    let store = SqliteReceiptStore::open(&path)?;
    // One writer round trip so the later health sample observes the seeded
    // verified head rather than racing writer-thread startup.
    store.flush_receipt_writes()?;

    let mut monetary = sample_intent("orphan-reconciled");
    monetary.side_effect_class = chio_kernel::receipt_store::SideEffectClass::Monetary;
    monetary.monetary = true;
    monetary.rail = Some("x402".to_string());
    monetary.rail_authorization_id = Some("auth-7".to_string());
    store.record_dispatch_intent(&monetary)?;

    let report = store.reconcile_dispatch_intents(&RailProvingReconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(report.monetary_reconciled, 1);
    assert_eq!(report.dead_lettered, 0);

    // The reconciled intent reaches its own terminal state carrying the rail
    // reference: the reconciler PROVED the outcome, so the row is neither
    // open nor an outcome-unknown dead letter.
    let connection = store.reader_connection_for_test()?;
    let (state, detail): (String, String) = connection.query_row(
        "SELECT state, resolution_detail FROM chio_dispatch_intents \
         WHERE request_id = 'orphan-reconciled'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    drop(connection);
    assert_eq!(state, "reconciled");
    assert!(
        detail.contains("tx-123"),
        "the terminal disposition names the rail reference: {detail}"
    );
    assert_eq!(store.open_dispatch_intent_count()?, 0);
    assert_eq!(store.dead_letter_dispatch_intent_count()?, 0);

    let health = store.receipt_store_health()?;
    assert!(
        health.healthy,
        "a rail-proven reconciliation is not an incident and must not flip health"
    );
    assert_eq!(health.dead_letter_dispatch_intents, 0);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Reconciler that proves every orphan's effect never ran, so each is safe
/// to replay.
struct ReplayProvingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for ReplayProvingReconciler {
    fn resolve(
        &self,
        _intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        Ok(chio_kernel::receipt_store::DispatchIntentResolution::SafeToReplay)
    }
}

#[test]
fn safe_to_replay_frees_the_request_id_for_a_fresh_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    // "Safe to replay" means the reconciler PROVED the effect never ran and
    // the resolution is to run the request again. The replay travels the
    // normal pre-dispatch path, which journals its own intent under the
    // same request id, so the proven-effectless row must not survive: the
    // request id is the journal's primary key, and any leftover row would
    // refuse the replay's insert and fail the request before the tool runs.
    let path = unique_db_path("chio-intents-safe-to-replay");
    let store = SqliteReceiptStore::open(&path)?;
    store.record_dispatch_intent(&sample_intent("req-replay"))?;

    let report = store.reconcile_dispatch_intents(&ReplayProvingReconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(report.replayed, 1);
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a proven-effectless row must not linger as an open crash marker"
    );

    // The replayed request journals a fresh intent under the same id.
    store.record_dispatch_intent(&sample_intent("req-replay"))?;
    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "the replay's own pre-dispatch insert must succeed after reconciliation"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn dead_letter_intent_flips_store_unhealthy() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-health");
    let store = SqliteReceiptStore::open(&path)?;

    // Health folds in `writer_serving_closed`, which reads closed until the
    // writer thread's one-time startup seed publishes a verified head. Wait
    // for one writer round trip so the sample observes the seeded head
    // rather than racing thread startup.
    store.flush_receipt_writes()?;

    // A clean store is healthy with zero intent counts.
    let clean = store.receipt_store_health()?;
    assert!(clean.healthy);
    assert_eq!(clean.open_dispatch_intents, 0);
    assert_eq!(clean.dead_letter_dispatch_intents, 0);

    // An open intent alone does not flip health: it is in flight, not
    // orphaned.
    store.record_dispatch_intent(&sample_intent("open-1"))?;
    let with_open = store.receipt_store_health()?;
    assert_eq!(with_open.open_dispatch_intents, 1);
    assert!(with_open.healthy, "an in-flight intent is not an incident");

    // Reconciling it into a dead-letter incident flips the store unhealthy.
    store.reconcile_dispatch_intents(&RecordingReconciler)?;
    let after = store.receipt_store_health()?;
    assert_eq!(after.dead_letter_dispatch_intents, 1);
    assert!(
        !after.healthy,
        "a dead-letter incident flips health to false"
    );
    assert_eq!(store.open_dispatch_intent_count()?, 0);
    assert_eq!(store.dead_letter_dispatch_intent_count()?, 1);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn stamped_receipt_schema_version(
    connection: &rusqlite::Connection,
) -> Result<i32, Box<dyn std::error::Error>> {
    Ok(connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn receipt_schema_revision_covers_the_dispatch_intent_journal(
) -> Result<(), Box<dyn std::error::Error>> {
    // A journal-bearing database must carry a schema revision above the
    // pre-journal one, so an older binary (which would neither reconcile
    // open intents nor surface them in health) refuses the file instead of
    // serving it while orphaned effects sit invisible.
    let path = unique_db_path("chio-intents-schema-revision");
    let store = SqliteReceiptStore::open(&path)?;
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        stamped_receipt_schema_version(&connection)?,
        1,
        "a freshly created journal-bearing store stamps revision 1"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn open_existing_migrates_a_pre_journal_database() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::dispatch_intents_table_exists;

    let path = unique_db_path("chio-intents-schema-migration");
    // Build a pre-journal database: create a full store, then rewind it by
    // dropping the journal table and stamping the pre-journal revision.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.flush_receipt_writes()?;
    }
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection
            .execute_batch("PRAGMA busy_timeout = 5000; DROP TABLE chio_dispatch_intents;")?;
        crate::stamp_schema_version(&connection, "receipt", 0)?;
    }

    // open_existing on the pre-journal file runs the additive migration: the
    // journal table exists afterwards and the current revision is stamped,
    // so an older binary refuses the migrated file from then on.
    {
        let store = SqliteReceiptStore::open_existing(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(
            dispatch_intents_table_exists(&connection)?,
            "open_existing must create the journal table on a pre-journal database"
        );
        assert_eq!(
            stamped_receipt_schema_version(&connection)?,
            1,
            "the migrated database is stamped with the journal revision"
        );
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn open_creates_dispatch_intents_table_and_open_existing_tolerates_absence(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::dispatch_intents_table_exists;

    let path = unique_db_path("chio-intents-schema");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(
            dispatch_intents_table_exists(&connection)?,
            "open() must create chio_dispatch_intents"
        );
    }
    // Reopening the same file via open_existing keeps the table (the
    // database is already at the journal revision, so no migration runs).
    {
        let store = SqliteReceiptStore::open_existing(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(dispatch_intents_table_exists(&connection)?);
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}
