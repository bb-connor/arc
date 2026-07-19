#[cfg(test)]
mod receipt_commit_actor_tests {
    use super::*;

    fn actor_test_receipt() -> Result<ChioReceipt, ReceiptStoreError> {
        let keypair = chio_core::crypto::Keypair::generate();
        ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: "rcpt-actor-test".to_string(),
                timestamp: 1,
                capability_id: "cap-actor".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                    serde_json::json!({}),
                )
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?,
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content".to_string(),
                policy_hash: "policy".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .map_err(|error| ReceiptStoreError::CryptoDecode(error.to_string()))
    }

    #[test]
    fn receipt_commit_actor_channel_has_fixed_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }

        let (response, _result) = mpsc::sync_channel(1);
        match sender.try_send(ReceiptCommitCommand::Flush(response)) {
            Err(mpsc::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                Err("commit actor channel disconnected unexpectedly".into())
            }
            Ok(()) => Err("commit actor channel accepted beyond fixed capacity".into()),
        }
    }

    #[test]
    fn receipt_commit_actor_append_fails_closed_when_queue_is_full(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }
        let actor = ReceiptCommitActor {
            sender,
            health,
            database_identity_file: None,
        };

        let error = actor.append(actor_test_receipt()?, "{}".to_string(), false);

        assert!(error
            .err()
            .ok_or("expected queue saturation error")?
            .to_string()
            .contains("sqlite receipt commit queue saturated"));
        Ok(())
    }

    #[test]
    fn receipt_commit_actor_flush_honors_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor {
            sender,
            health,
            database_identity_file: None,
        };

        let error = actor.flush_with_timeout(Duration::from_millis(1));

        match error.err().ok_or("expected flush timeout error")? {
            ReceiptStoreError::Timeout {
                operation,
                timeout_ms,
            } => {
                assert_eq!(operation, "sqlite receipt commit flush");
                assert_eq!(timeout_ms, 1);
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        Ok(())
    }

    #[test]
    fn run_write_executes_jobs_serially_on_the_writer_thread(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-run-write-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        let first_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;
        let second_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;

        assert_eq!(
            first_thread, second_thread,
            "all write jobs must run on the single writer thread"
        );
        assert_ne!(
            first_thread,
            std::thread::current().id(),
            "write jobs must not run on the caller thread"
        );

        // The closure really gets a usable writer connection.
        let journal_mode = writer.run_write(|connection| {
            connection
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .map_err(ReceiptStoreError::from)
        })?;
        assert!(journal_mode.eq_ignore_ascii_case("wal"));

        // Inflight accounting drains back to zero after the jobs complete.
        assert_eq!(
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst),
            0
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn run_write_fails_closed_when_queue_is_full() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
            database_identity_file: None,
        };

        let error = handle.run_write(|_connection| Ok(()));

        assert!(error
            .err()
            .ok_or("expected queue saturation error")?
            .to_string()
            .contains("sqlite receipt commit queue saturated"));
        assert_eq!(
            health.inflight.load(Ordering::SeqCst),
            0,
            "speculative inflight increment must be undone on saturation"
        );
        assert_eq!(health.saturated_total.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// A writer-routed `Write` job (liability write, manual checkpoint creation)
    /// must keep `writer_inflight` nonzero for the DURATION of the job, not just
    /// at enqueue, so a health poll during a slow or stuck Write does not report
    /// `inflight: 0` and hide active writer work. The `WriterInflightGuard`
    /// holds the count until the job completes, mirroring the Append path.
    #[test]
    fn write_job_holds_inflight_for_its_duration() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-write-inflight-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        // Drain any open-time writer activity to a known baseline before running
        // the coordinated job.
        let drained_baseline = wait_until(|| {
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst)
                == 0
        });
        assert!(drained_baseline, "writer failed to drain to baseline");

        // Coordinate a Write job that blocks inside its closure until released.
        let (started_tx, started_rx) = mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
        let worker = std::thread::spawn(move || {
            writer.run_write(move |_connection| {
                // Signal that the job is now executing on the writer thread, then
                // block until the test releases it.
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
        });

        // The job is running: inflight must be nonzero for the DURATION of the
        // Write, not merely at enqueue.
        started_rx.recv().map_err(|_| "write job never started")?;
        assert_eq!(
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst),
            1,
            "a running Write job must report inflight > 0"
        );

        // Release the job and confirm inflight drains back to baseline. The
        // `WriterInflightGuard` decrements just BEFORE the caller's response is
        // delivered, so this is already at baseline once the worker join
        // returns; poll defensively regardless.
        release_tx.send(())?;
        worker
            .join()
            .map_err(|_| "write worker thread panicked")??;
        let drained = wait_until(|| {
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst)
                == 0
        });
        assert!(
            drained,
            "inflight must return to baseline after the Write completes"
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    /// The `WriterInflightGuard` decrement must be SYNCHRONOUS with
    /// caller-return: the guard drops IMMEDIATELY BEFORE each `respond(...)`,
    /// matching the Append path's decrement-then-fan-out ordering
    /// (`commit_receipt_batch`), so caller-return implies the decrement already
    /// happened. If the guard instead dropped at the END of the Write arm (after
    /// `respond(...)` unblocked `run_write`), a caller could return while
    /// `inflight` was still counted, the exact window that would make
    /// `run_write_executes_jobs_serially_on_the_writer_thread` intermittently
    /// observe `inflight == 1`. This asserts the guarantee DIRECTLY and
    /// deterministically (no `wait_until`): right after `run_write` returns,
    /// `inflight` reads 0 on every one of many iterations.
    #[test]
    fn write_decrements_inflight_before_returning_to_caller(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-write-inflight-order-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        // Drain any open-time writer activity to a known baseline first.
        let drained_baseline = wait_until(|| {
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst)
                == 0
        });
        assert!(drained_baseline, "writer failed to drain to baseline");

        // Many iterations to expose the ordering race: if the guard dropped
        // AFTER the response reached the caller (while the writer thread still
        // had the head snapshot, error clear, connection drop and catch-up build
        // to run), this load could intermittently observe 1. Because the
        // decrement precedes the response, caller-return happens-before this
        // load and it must read 0 on EVERY iteration with no polling.
        for iteration in 0..512 {
            writer.run_write(|_connection| Ok(()))?;
            let observed = store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst);
            assert_eq!(
                observed, 0,
                "caller returned from run_write with inflight still counted \
                 (iteration {iteration}); the decrement must precede the response"
            );
        }

        let _ = fs::remove_file(path);
        Ok(())
    }

    /// Poll `predicate` for up to ~1s (1ms steps), returning whether it held.
    fn wait_until(predicate: impl Fn() -> bool) -> bool {
        for _ in 0..1_000 {
            if predicate() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        predicate()
    }
}
