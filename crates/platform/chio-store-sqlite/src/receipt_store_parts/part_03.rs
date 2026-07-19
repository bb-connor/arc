#[cfg(test)]
mod receipt_commit_actor_tests {
    use super::*;

    #[test]
    fn writer_health_starts_with_a_poisoned_head_until_seeding_clears_it() {
        // The commit writer seeds its verified head asynchronously on the actor
        // thread. Until that seed succeeds, durable persistence is unproven, so a
        // freshly constructed health mirror must report a poisoned head. Starting
        // open would let a corrupt or still-attaching store pass
        // `writer_serving_closed` and execute a tool before its first append can
        // reject, which is exactly the fail-open window the pre-dispatch gate
        // exists to prevent.
        let health = ReceiptCommitWriterHealth::default();
        assert!(
            health.head_poisoned.load(Ordering::SeqCst),
            "writer health must start head-poisoned (serving closed) until a seeded head clears it"
        );
    }

    fn idle_writer() -> SupervisedThread {
        SupervisedThread::spawn(
            SupervisorConfig {
                name: "test-idle-writer",
                tcb_critical: true,
                trip_after: 1,
                max_restarts: 1,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(1),
            },
            |shutdown| {
                while !shutdown.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                SupervisedOutcome::Shutdown
            },
        )
    }

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
            writer: idle_writer(),
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
            writer: idle_writer(),
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
    fn append_with_timeout_maps_to_timeout_and_keeps_inflight_elevated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A commit actor whose worker never drains: try_send queues the command,
        // but no reply ever arrives, so the bounded wait elapses.
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor {
            sender,
            health,
            writer: idle_writer(),
            database_identity_file: None,
        };
        let inflight_before = actor.health.inflight.load(Ordering::SeqCst);

        let start = std::time::Instant::now();
        let error = actor.append_with_timeout(
            actor_test_receipt()?,
            "{}".to_string(),
            false,
            Duration::from_millis(250),
        );
        assert!(start.elapsed() < Duration::from_secs(2));

        match error.err().ok_or("expected append timeout error")? {
            ReceiptStoreError::Timeout { operation, .. } => {
                assert_eq!(operation, "sqlite receipt commit append");
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        // The timeout side must not decrement inflight; ownership stays with the
        // actor, so a genuinely wedged writer keeps inflight elevated.
        assert_eq!(
            actor.health.inflight.load(Ordering::SeqCst),
            inflight_before + 1
        );
        assert!(actor.health.failed_total.load(Ordering::SeqCst) >= 1);
        Ok(())
    }

    #[test]
    fn enqueue_on_a_disconnected_actor_records_writer_dead(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The commit actor has exited, so its receiver is gone and `try_send`
        // fails Disconnected before any response channel exists. That enqueue
        // path must record the writer death, or the next liveness sample keeps
        // reporting the writer Healthy and admits a tool side effect whose
        // receipt can never be persisted.
        let (sender, receiver) = receipt_commit_channel();
        drop(receiver);
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor {
            sender,
            health,
            writer: idle_writer(),
            database_identity_file: None,
        };

        let error = actor.append_with_timeout(
            actor_test_receipt()?,
            "{}".to_string(),
            false,
            Duration::from_millis(250),
        );
        assert!(error
            .err()
            .ok_or("expected writer-unavailable error")?
            .to_string()
            .contains("unavailable"));

        let counters = actor.writer_counters();
        assert!(
            counters
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("unavailable")),
            "the disconnected enqueue must record the writer death"
        );
        assert_eq!(
            classify_writer_liveness(
                &counters,
                10_000,
                RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64,
                None,
                1_000_000,
            ),
            chio_kernel::ReceiptWriterLiveness::Dead,
            "a disconnected writer must classify as Dead so admission stops"
        );
        Ok(())
    }

    #[test]
    fn note_accept_restamps_backlog_start_only_on_a_fresh_backlog() {
        let health = ReceiptCommitWriterHealth::default();

        // 0 -> 1 begins a backlog and stamps a real start time.
        health.note_accept(0);
        assert_ne!(
            health.backlog_started_unix_ms.load(Ordering::SeqCst),
            0,
            "the first enqueue of a backlog must stamp its start"
        );

        // 1 -> 2 grows an ongoing backlog and must NOT move its start.
        health.backlog_started_unix_ms.store(1, Ordering::SeqCst);
        health.note_accept(1);
        assert_eq!(
            health.backlog_started_unix_ms.load(Ordering::SeqCst),
            1,
            "a growing backlog must keep its original start"
        );

        // 0 -> 1 after the writer drained begins a NEW backlog and restamps.
        health.backlog_started_unix_ms.store(1, Ordering::SeqCst);
        health.note_accept(0);
        assert_ne!(
            health.backlog_started_unix_ms.load(Ordering::SeqCst),
            1,
            "a fresh backlog after draining must restamp the start"
        );
    }

    #[test]
    fn committed_write_clears_a_stale_bounded_timeout_marker() {
        let health = ReceiptCommitWriterHealth::default();
        // An earlier bounded writer-routed op timed out and left the marker set
        // while its work was still in flight.
        if let Ok(mut last_error) = health.last_error.lock() {
            *last_error = Some("sqlite receipt commit write timed out".to_string());
        }
        // The writer catches up and a later write commits.
        record_write_job_outcome(&health, true);
        let cleared = match health.last_error.lock() {
            Ok(guard) => guard.is_none(),
            Err(_) => false,
        };
        assert!(
            cleared,
            "a committed write must clear the stale timeout marker so a later merely in-flight write is not misclassified Wedged"
        );
        assert_eq!(health.committed_total.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn committed_write_preserves_a_genuine_writer_error() {
        let health = ReceiptCommitWriterHealth::default();
        // A poisoned-head / checkpoint fault is not a stall marker and must
        // survive a later commit so the store keeps reporting the real fault.
        if let Ok(mut last_error) = health.last_error.lock() {
            *last_error = Some("receipt store verified head is unavailable".to_string());
        }
        record_write_job_outcome(&health, true);
        let preserved = match health.last_error.lock() {
            Ok(guard) => guard.as_deref() == Some("receipt store verified head is unavailable"),
            Err(_) => false,
        };
        assert!(
            preserved,
            "a committed write must not clear an unrelated writer error"
        );
    }

    #[test]
    fn run_write_receipt_with_timeout_fails_closed_when_writer_never_drains(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Child receipts persist through `run_write_receipt`. Its bounded variant
        // must fail closed on a wedged writer instead of blocking the caller (and
        // the kernel-wide receipt write lock it holds) forever.
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
            database_identity_file: None,
        };
        let inflight_before = health.inflight.load(Ordering::SeqCst);

        let start = std::time::Instant::now();
        let error =
            handle.run_write_receipt_with_timeout(|_connection| Ok(()), Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(2));

        match error.err().ok_or("expected write timeout error")? {
            ReceiptStoreError::Timeout { operation, .. } => {
                assert_eq!(operation, "sqlite receipt commit write");
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        // Ownership of the queued job stays with the actor, so the timeout side
        // must leave inflight elevated (the honest wedged-writer signal).
        assert_eq!(health.inflight.load(Ordering::SeqCst), inflight_before + 1);
        assert!(health.failed_total.load(Ordering::SeqCst) >= 1);
        Ok(())
    }

    #[test]
    fn run_write_with_timeout_fails_closed_when_writer_never_drains(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The hot-path capability snapshot persists through `run_write_with_timeout`.
        // Its bounded metadata variant must fail closed on a wedged writer instead
        // of blocking the caller forever.
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
            database_identity_file: None,
        };
        let inflight_before = health.inflight.load(Ordering::SeqCst);

        let start = std::time::Instant::now();
        let error = handle.run_write_with_timeout(|_connection| Ok(()), Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(2));

        match error.err().ok_or("expected write timeout error")? {
            ReceiptStoreError::Timeout { operation, .. } => {
                assert_eq!(operation, "sqlite receipt commit write");
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        // Ownership of the queued job stays with the actor, so the timeout side
        // must leave inflight elevated (the honest wedged-writer signal).
        assert_eq!(health.inflight.load(Ordering::SeqCst), inflight_before + 1);
        assert!(health.failed_total.load(Ordering::SeqCst) >= 1);
        Ok(())
    }

    #[test]
    fn disconnected_bounded_write_records_writer_death_for_liveness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The commit actor accepts a bounded child-receipt write, then dies
        // without responding, disconnecting the caller's response channel. The
        // write must record the writer death so the next pre-dispatch liveness
        // sample reports the writer Dead and denies admission, instead of
        // sampling Healthy once inflight is compensated and failed_total matches
        // accepted_total.
        let (sender, receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
            database_identity_file: None,
        };
        // Actor thread: take the one queued command and drop it (die mid-flight),
        // which drops the deferred responder and disconnects the caller.
        let actor = std::thread::spawn(move || {
            if let Ok(command) = receiver.recv() {
                drop(command);
            }
            drop(receiver);
        });

        let error =
            handle.run_write_receipt_with_timeout(|_connection| Ok(()), Duration::from_secs(5));
        actor.join().map_err(|_| "actor thread panicked")?;
        assert!(error.is_err(), "a disconnected writer must fail closed");

        let counters = ReceiptCommitActor {
            sender: receipt_commit_channel().0,
            health: Arc::clone(&health),
            writer: idle_writer(),
            database_identity_file: None,
        }
        .writer_counters();
        assert!(
            counters
                .last_error
                .as_deref()
                .is_some_and(|reason| reason.contains("unavailable")),
            "writer death must be recorded for the liveness probe"
        );
        assert_eq!(
            classify_writer_liveness(
                &counters,
                10_000,
                RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64,
                None,
                current_unix_ms(),
            ),
            chio_kernel::ReceiptWriterLiveness::Dead
        );
        Ok(())
    }

    #[test]
    fn disconnected_reseed_flips_writer_liveness_dead_immediately(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A disconnected admin send (reseed after the commit actor has already
        // exited) is the first observation that the writer is gone. It must flip
        // liveness to Dead now, so the pre-dispatch gate denies admission before
        // a later append reconfirms the death.
        let path = std::env::temp_dir().join(format!(
            "chio-reseed-dead-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut store = SqliteReceiptStore::open(&path)?;

        // Replace the live commit actor with one whose receiver is dropped, so
        // the next admin send observes a dead actor. Overwriting the field drops
        // the original sender, letting the original actor thread exit cleanly.
        let (sender, receiver) = receipt_commit_channel();
        drop(receiver);
        store.receipt_commit_actor = ReceiptCommitActor {
            sender,
            health: Arc::new(ReceiptCommitWriterHealth::default()),
            writer: idle_writer(),
            database_identity_file: None,
        };

        let error = match store.reseed_verified_head() {
            Ok(()) => return Err("reseed against a dead actor must fail closed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unavailable"));

        assert_eq!(
            store.writer_liveness(Duration::from_secs(60)),
            chio_kernel::ReceiptWriterLiveness::Dead,
            "a disconnected reseed must flip writer liveness to Dead immediately"
        );

        let _ = std::fs::remove_file(&path);
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
