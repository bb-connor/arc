    #[test]
    fn expired_terminal_cleanup_rolls_back_the_batch_on_late_corruption() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("terminal-cleanup-rollback.sqlite");
        let now_unix_ms = current_unix_ms();
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &path,
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("rollback security store: {error}")),
        );
        let plans = ["action-cleanup-rollback-a", "action-cleanup-rollback-b"]
            .into_iter()
            .map(|action_id| {
                install_due_sqlite_plan(&store, action_id, now_unix_ms.saturating_sub(1))
            })
            .collect::<Vec<_>>();
        let port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-cleanup-rollback",
            "incarnation-cleanup-rollback-first",
            100,
        );
        let initial_work = port
            .claim(0)
            .unwrap_or_else(|error| panic!("rollback initial claim: {error}"));
        assert_eq!(initial_work.len(), 2);
        let mut terminal_work = Vec::with_capacity(initial_work.len());
        for (index, work) in initial_work.iter().enumerate() {
            let plan = plans
                .iter()
                .find(|plan| plan.action_id == work.action_id)
                .unwrap_or_else(|| panic!("rollback plan missing"));
            let reclaimed = record_retry_and_reclaim(
                &store,
                &clock,
                &port,
                work,
                u64::try_from(index)
                    .unwrap_or_else(|error| panic!("rollback tick conversion: {error}"))
                    .saturating_add(1),
                RecordId::new(format!(
                    "cleanup-rollback-retry-{}",
                    work.action_id.as_str()
                ))
                .unwrap_or_else(|error| panic!("rollback retry transition: {error}")),
            );
            ResponseStateMachine::new(Arc::clone(&store))
                .transition_scheduled(
                    plan,
                    &reclaimed,
                    &ResponseTransitionRequest {
                        expected_generation: plan.generation,
                        target_state: ResponseState::Cancelled,
                        occurred_at_unix_ms: clock.now(),
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )
                .unwrap_or_else(|error| panic!("rollback terminal transition: {error}"));
            terminal_work.push(reclaimed);
        }
        let cleanup_now = terminal_work
            .iter()
            .map(|work| work.lease_expires_at_unix_ms)
            .max()
            .unwrap_or_else(|| panic!("rollback expiry missing"))
            .saturating_add(1);
        drop(port);
        drop(store);
        clock.set(cleanup_now);

        let reopened = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &path,
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("rollback store reopen: {error}")),
        );
        let restarted = sqlite_worker_port(
            reopened,
            clock,
            "worker-cleanup-rollback",
            "incarnation-cleanup-rollback-restart",
            100,
        );
        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("rollback corruption connection: {error}"));
        connection
            .execute(
                r#"
                UPDATE security_response_plans
                SET body_hash = zeroblob(32)
                WHERE tenant_id = ?1 AND action_id = ?2
                "#,
                rusqlite::params![
                    terminal_work[1].tenant_id.as_str(),
                    terminal_work[1].action_id.as_str()
                ],
            )
            .unwrap_or_else(|error| panic!("rollback corruption write: {error}"));
        drop(connection);

        assert!(restarted.claim(0).is_err());
        let connection = rusqlite::Connection::open(path)
            .unwrap_or_else(|error| panic!("rollback readback connection: {error}"));
        let durable_counts = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_scheduler_leases),
                    (SELECT COUNT(*) FROM security_scheduler_retries),
                    (SELECT COUNT(*) FROM security_transitions
                     WHERE transition_kind = 'scheduler_expired_terminal_cleanup')
                "#,
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap_or_else(|error| panic!("rollback durable counts: {error}"));
        assert_eq!(durable_counts, (2, 2, 0));
    }

    #[test]
    fn sqlite_worker_claims_simultaneously_due_actions_transactionally_in_deterministic_order() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let now_unix_ms = current_unix_ms();
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                directory.path().join("response-order.sqlite"),
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        let due_at_unix_ms = now_unix_ms.saturating_sub(1);
        for action_id in ["action-order-z", "action-order-a", "action-order-m"] {
            install_due_sqlite_plan(&store, action_id, due_at_unix_ms);
        }
        let first_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-order",
            "incarnation-sqlite-order-first",
            100,
        );

        let claimed = first_port
            .claim(0)
            .unwrap_or_else(|error| panic!("ordered claim: {error}"));
        let claimed_action_ids = claimed
            .iter()
            .map(|work| work.action_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            claimed_action_ids,
            vec!["action-order-a", "action-order-m", "action-order-z"]
        );
        assert!(claimed
            .windows(2)
            .all(|pair| pair[0].fencing_token < pair[1].fencing_token));
        for work in &claimed {
            store
                .validate_lease(work)
                .unwrap_or_else(|error| panic!("claimed lease is invalid: {error}"));
        }

        let contender = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-order-contender",
            "incarnation-sqlite-order-contender",
            100,
        );
        assert!(contender
            .claim(0)
            .unwrap_or_else(|error| panic!("competing claim: {error}"))
            .is_empty());
        drop(contender);
        drop(first_port);

        clock.set(claimed[0].lease_expires_at_unix_ms.saturating_add(1));
        let restarted_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-order",
            "incarnation-sqlite-order-takeover",
            100,
        );
        let replayed = restarted_port
            .claim(0)
            .unwrap_or_else(|error| panic!("takeover ordered claim: {error}"));
        assert_eq!(
            replayed
                .iter()
                .map(|work| work.action_id.as_str())
                .collect::<Vec<_>>(),
            claimed_action_ids
        );
        assert!(replayed.iter().zip(&claimed).all(|(successor, stale)| {
            successor.lease_owner_id == stale.lease_owner_id
                && successor.fencing_token > stale.fencing_token
        }));
        let restarted = ProductionResponseWorker::new_for_test(restarted_port)
            .unwrap_or_else(|error| panic!("restarted worker: {error}"));
        restarted
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("restarted worker shutdown: {error}"));

        let failure_path = directory
            .path()
            .join("response-order-atomic-failure.sqlite");
        let failure_clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let failure_store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &failure_path,
                Arc::clone(&failure_clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("failure security store: {error}")),
        );
        for action_id in [
            "action-order-atomic-z",
            "action-order-atomic-a",
            "action-order-atomic-m",
        ] {
            install_due_sqlite_plan(&failure_store, action_id, due_at_unix_ms);
        }
        let connection = rusqlite::Connection::open(&failure_path)
            .unwrap_or_else(|error| panic!("failure trigger connection: {error}"));
        let fence_sequence_before = connection
            .query_row(
                "SELECT COALESCE(MAX(last_fencing_token), 0) FROM security_scheduler_fence_sequences",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("initial fence sequence: {error}"));
        connection
            .execute_batch(
                r#"
                CREATE TRIGGER fail_scheduler_claim_mid_batch
                BEFORE INSERT ON security_scheduler_leases
                WHEN NEW.action_id = 'action-order-atomic-m'
                BEGIN
                    SELECT RAISE(ABORT, 'forced scheduler claim failure');
                END;
                "#,
            )
            .unwrap_or_else(|error| panic!("install claim failure trigger: {error}"));
        drop(connection);
        let failure_port = sqlite_worker_port(
            Arc::clone(&failure_store),
            failure_clock,
            "worker-sqlite-order-atomic-failure",
            "incarnation-sqlite-order-atomic-failure",
            5_000,
        );
        assert!(failure_port.claim(0).is_err());

        let connection = rusqlite::Connection::open(failure_path)
            .unwrap_or_else(|error| panic!("failure readback connection: {error}"));
        let durable_counts = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_scheduler_leases),
                    (SELECT COUNT(*) FROM security_scheduler_claims),
                    (SELECT COALESCE(MAX(last_fencing_token), 0)
                       FROM security_scheduler_fence_sequences)
                "#,
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap_or_else(|error| panic!("claim rollback readback: {error}"));
        assert_eq!(durable_counts, (0, 0, fence_sequence_before));
    }

    #[test]
    fn sqlite_worker_stale_fence_loses_after_expiry_takeover() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("response-fence.sqlite"))
                .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        let now_unix_ms = current_unix_ms();
        install_due_sqlite_plan(&store, "action-sqlite-fence", now_unix_ms.saturating_sub(1));
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let stale_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-stale",
            "incarnation-sqlite-stale",
            150,
        );
        let _stale_worker = ProductionResponseWorker::new_for_test(Arc::clone(&stale_port))
            .unwrap_or_else(|error| panic!("stale worker: {error}"));
        clock.set(current_unix_ms());
        let stale_work = stale_port
            .claim(0)
            .unwrap_or_else(|error| panic!("stale claim: {error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("stale work missing"));

        std::thread::sleep(Duration::from_millis(200));
        let takeover_now = current_unix_ms();
        clock.set(takeover_now);
        let takeover_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-takeover",
            "incarnation-sqlite-takeover",
            5_000,
        );
        let takeover_work = takeover_port
            .claim(0)
            .unwrap_or_else(|error| panic!("takeover claim: {error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("takeover work missing"));
        assert!(takeover_work.fencing_token > stale_work.fencing_token);
        assert!(matches!(
            stale_port.scheduler.process(&stale_work, takeover_now),
            Ok(SchedulerWorkOutcome::LeaseLost { .. })
        ));
        let takeover = ProductionResponseWorker::new_for_test(takeover_port)
            .unwrap_or_else(|error| panic!("takeover worker: {error}"));
        takeover
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("takeover shutdown: {error}"));
    }

    #[test]
    fn production_worker_restart_recovers_after_ack_loss_without_duplicate_completion() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(ResponseWorkerTickError::AckLost),
            Ok(tick("action-recovered")),
        ]));
        let first = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("first worker: {error}"));
        assert!(matches!(
            first.tick_once(),
            Err(ResponseWorkerTickError::AckLost)
        ));

        let restarted = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("restarted worker: {error}"));
        let recovered = restarted
            .tick_once()
            .unwrap_or_else(|error| panic!("recovery tick: {error}"));
        assert_eq!(recovered.completed_action_ids.len(), 1);
        assert_eq!(
            recovered.completed_action_ids[0].as_str(),
            "action-recovered"
        );
    }

    #[test]
    fn production_worker_surfaces_stale_fence_as_lease_loss_not_completion() {
        let stale = ResponseWorkerTick {
            tenant_id: tenant(),
            declassification_receipts_appended: 0,
            declassification_receipts_acknowledged: 0,
            declassification_receipts_pending: 0,
            declassification_receipts_compacted: 0,
            claimed: 1,
            completed_action_ids: Vec::new(),
            retry_action_ids: Vec::new(),
            lease_lost_action_ids: vec![
                ActionId::new("action-stale").unwrap_or_else(|error| panic!("action id: {error}"))
            ],
        };
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(stale)]));
        let worker = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("worker: {error}"));
        let report = worker
            .tick_once()
            .unwrap_or_else(|error| panic!("stale tick: {error}"));
        assert!(report.completed_action_ids.is_empty());
        assert_eq!(report.lease_lost_action_ids.len(), 1);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
    }

    #[test]
    fn worker_progress_deadline_has_an_absolute_validated_boundary() {
        let rapid = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(1),
        };
        assert_eq!(rapid.progress_deadline(), MIN_WORKER_PROGRESS_DEADLINE);

        let boundary = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30),
        };
        let validated = boundary
            .validate()
            .unwrap_or_else(|error| panic!("valid progress boundary rejected: {error}"));
        assert_eq!(validated, boundary);
        assert_eq!(boundary.progress_deadline(), MAX_WORKER_PROGRESS_DEADLINE);

        let above_boundary = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30) + Duration::from_nanos(1),
        };
        assert!(matches!(
            above_boundary.validate(),
            Err(ResponseWorkerTickError::InvalidConfig)
        ));
    }

    #[test]
    fn pending_declassification_receipts_keep_worker_health_degraded() {
        let mut pending = tick("action-with-pending-evidence");
        pending.declassification_receipts_pending = 3;
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(pending)]));
        let worker = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("worker: {error}"));

        worker
            .tick_once()
            .unwrap_or_else(|error| panic!("pending evidence tick: {error}"));

        let health = worker.health();
        assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Degraded);
        assert_eq!(
            health.last_error.as_deref(),
            Some("3 declassification receipts remain pending")
        );
    }

    #[test]
    fn post_loop_cleanup_releases_owned_work_and_is_idempotent() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
        let worker = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}"));
        worker
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("first shutdown: {error}"));
        worker
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("second shutdown: {error}"));
        assert_eq!(port.shutdown_calls(), 1);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[test]
    fn reaper_spawn_failure_retains_join_ownership_for_later_recovery() {
        let registry = Arc::new(ResponseWorkerReaperRegistry::new());
        registry.fail_next_spawn.store(true, Ordering::Release);
        let permit = registry
            .acquire_without_service_for_test()
            .unwrap_or_else(|error| panic!("join permit: {error}"));
        let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let worker_for_thread = Arc::clone(&worker);
        let join = std::thread::spawn(move || worker_for_thread.complete_shutdown_after_loop());

        registry.enqueue(ResponseWorkerJoinJob {
            join,
            worker: Arc::clone(&worker),
            _permit: permit,
        });

        {
            let state = registry.lock_state();
            assert_eq!(state.jobs.len(), 1);
            assert_eq!(state.join_owners, 1);
            assert!(state.reaper.is_none());
        }
        let ResponseWorkerJoinJob {
            join,
            worker,
            _permit,
        } = registry
            .take_retained_job_for_test()
            .unwrap_or_else(|| panic!("retained join ownership was lost"));
        join_response_worker_thread(join, &worker)
            .unwrap_or_else(|error| panic!("retained join: {error}"));
        drop(_permit);
        assert_eq!(registry.lock_state().join_owners, 0);
        assert!(worker.thread_joined.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls(), 1);
    }

    #[test]
    fn join_registry_reservations_bound_retained_worker_growth() {
        let registry = Arc::new(ResponseWorkerReaperRegistry::new());
        let mut permits = Vec::new();
        for _ in 0..MAX_RESPONSE_WORKER_JOIN_OWNERS {
            permits.push(
                registry
                    .acquire_without_service_for_test()
                    .unwrap_or_else(|error| panic!("join permit: {error}")),
            );
        }
        assert!(matches!(
            registry.acquire_without_service_for_test(),
            Err(ResponseWorkerTickError::WorkerReaperCapacity)
        ));
        drop(permits);
        assert_eq!(registry.lock_state().join_owners, 0);
    }

    #[tokio::test]
    async fn production_worker_allows_only_one_background_loop() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(tick(
            "initial-publication-readiness",
        ))]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let config = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30),
        };
        let mut handle = worker
            .start_parked(config)
            .await
            .unwrap_or_else(|error| panic!("first start: {error}"));

        assert!(matches!(
            worker.start_parked(config).await,
            Err(ResponseWorkerTickError::WorkerAlreadyRunning)
        ));

        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));

        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        assert_eq!(port.shutdown_calls(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_owned_thread_survives_caller_starvation_and_joins_before_restart() {
        let ticks = (0..64)
            .map(|_| Ok(tick("worker-owned-thread-progress")))
            .collect();
        let port = Arc::new(ScriptedWorkerPort::with_ticks(ticks));

        for generation in 0..2 {
            let worker = Arc::new(
                ProductionResponseWorker::new_for_test(Arc::clone(&port))
                    .unwrap_or_else(|error| panic!("worker {generation}: {error}")),
            );
            let mut handle = worker
                .start_parked(ProductionResponseWorkerLoopConfig {
                    tick_interval: Duration::from_millis(10),
                })
                .await
                .unwrap_or_else(|error| panic!("start worker {generation}: {error}"));
            handle
                .arm()
                .await
                .unwrap_or_else(|error| panic!("arm worker {generation}: {error}"));
            handle
                .release_publication()
                .unwrap_or_else(|error| panic!("publish worker {generation}: {error}"));
            handle
                .wait_for_publication_readiness()
                .await
                .unwrap_or_else(|error| {
                    panic!("publication readiness for worker {generation}: {error}")
                });
            let completed_before_starvation = worker.health().ticks_completed;

            std::thread::sleep(Duration::from_millis(100));

            let completed_after_starvation = worker.health().ticks_completed;
            assert!(completed_after_starvation > completed_before_starvation);
            worker
                .ensure_ready()
                .unwrap_or_else(|error| panic!("worker {generation} stalled: {error}"));
            handle
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("shutdown worker {generation}: {error}"));
            assert!(!worker.task_live.load(Ordering::Acquire));
            assert!(worker.shutdown_is_complete());
            assert!(handle.join.is_none());
        }

        assert_eq!(port.shutdown_calls(), 2);
    }

    #[test]
    fn progress_deadline_begins_when_the_worker_reaches_publication_readiness() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
        let worker = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("worker: {error}"));
        worker.configure_progress(Duration::from_millis(1));
        worker.task_live.store(true, Ordering::Release);
        worker
            .mark_publication_released()
            .unwrap_or_else(|error| panic!("release publication: {error}"));

        std::thread::sleep(Duration::from_millis(20));
        worker
            .ensure_ready()
            .unwrap_or_else(|error| panic!("unobserved publication stalled: {error}"));

        worker
            .mark_publication_ready()
            .unwrap_or_else(|error| panic!("mark publication ready: {error}"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerProgressStalled { .. })
        ));
    }

    #[tokio::test]
    async fn crashed_worker_thread_revokes_liveness_before_the_progress_deadline() {
        let crash = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.worker-thread-crash")
                .unwrap_or_else(|error| panic!("worker crash code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Ok(tick("initial-publication-readiness")),
            Err(crash),
        ]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while worker.health().lifecycle != ResponseWorkerLifecycle::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("worker thread did not report its crash"));

        assert!(!handle.is_running());
        assert!(matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerStopped)
        ));
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Failed);

        assert!(handle.shutdown().await.is_err());
        assert_eq!(port.shutdown_calls(), 1);
    }

    #[tokio::test]
    async fn parked_worker_commit_failure_stops_with_zero_ticks() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(tick(
            "action-must-not-run",
        ))]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
            worker: Arc::clone(&worker),
        });
        let registry = ActiveDefenseServiceRegistry::default();
        registry
            .reserve_exact(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        tokio::task::yield_now().await;
        assert_eq!(port.tick_calls(), 0);
        assert!(registry.snapshot().is_none());

        port.set_ready(false);
        let release_called = AtomicBool::new(false);
        assert!(registry
            .commit_reserved_exact_with_release(&services, || {
                release_called.store(true, Ordering::Release);
                handle.release_publication()
            })
            .is_err());
        assert!(!release_called.load(Ordering::Acquire));
        assert!(registry.snapshot().is_none());
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("parked shutdown: {error}"));
        assert_eq!(port.tick_calls(), 0);
        assert_eq!(port.shutdown_calls(), 1);
        registry
            .cancel_reserved_exact(&services)
            .unwrap_or_else(|error| panic!("cancel reserve: {error}"));
    }

    #[tokio::test]
    async fn publication_remains_unready_until_the_first_tick_completes() {
        let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
            worker: Arc::clone(&worker),
        });
        let registry = ActiveDefenseServiceRegistry::default();
        registry
            .reserve_exact(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_secs(30),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        assert!(registry.snapshot().is_none());
        assert!(!port.tick_started.load(Ordering::Acquire));

        registry
            .commit_reserved_exact_with_release(&services, || handle.release_publication())
            .unwrap_or_else(|error| panic!("publish: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("initial publication tick did not start"));

        assert!(registry.snapshot().is_some());
        assert!(!handle.is_running());
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Running);
        assert!(matches!(
            services.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerPublicationPending)
        ));
        port.release();
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        assert!(handle.is_running());
        let health = worker.health();
        assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
        assert!(health.ticks_completed >= 1);
        services
            .ensure_ready()
            .unwrap_or_else(|error| panic!("published services are not ready: {error}"));
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        registry
            .unpublish_exact(&services)
            .unwrap_or_else(|error| panic!("unpublish: {error}"));
    }

    #[tokio::test]
    async fn cancelled_publication_wait_transfers_join_ownership_without_blocking_drop() {
        let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_secs(30),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("initial publication tick did not start"));

        let startup = async move {
            handle.wait_for_publication_readiness().await?;
            Ok::<ProductionResponseWorkerHandle, ResponseWorkerTickError>(handle)
        };
        assert!(tokio::time::timeout(Duration::from_millis(20), startup)
            .await
            .is_err());
        assert!(worker.shutdown_requested.load(Ordering::Acquire));
        assert!(!worker.thread_joined.load(Ordering::Acquire));

        port.release();
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .unwrap_or_else(|_| panic!("cancelled startup worker did not stop"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !worker.thread_joined.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("cancelled startup worker thread was not joined"));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn initial_tick_retries_non_crash_failures_on_the_configured_cadence() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(ResponseWorkerTickError::Port(PortError::unavailable())),
            Err(ResponseWorkerTickError::Port(PortError::unavailable())),
            Ok(tick("initial-retry-success")),
        ]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));

        let health = worker.health();
        assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
        assert_eq!(health.ticks_attempted, 3);
        assert_eq!(health.ticks_completed, 1);
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
    }

    #[tokio::test]
    async fn initial_tick_deadline_exhaustion_fails_publication_and_joins_the_thread() {
        let failures = (0..8)
            .map(|_| Err(ResponseWorkerTickError::Port(PortError::unavailable())))
            .collect();
        let port = Arc::new(ScriptedWorkerPort::with_ticks(failures));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));

        assert!(matches!(
            handle.wait_for_publication_readiness().await,
            Err(ResponseWorkerTickError::WorkerInitialTick(_))
        ));
        assert!(handle.shutdown().await.is_err());
        assert!(!worker.task_live.load(Ordering::Acquire));
        assert!(handle.join.is_none());
    }

    #[tokio::test]
    async fn immediate_post_release_crash_keeps_the_degraded_services_published() {
        let failure = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.post_release_crash")
                .unwrap_or_else(|error| panic!("error code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Err(failure)]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(port)
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
            worker: Arc::clone(&worker),
        });
        let registry = ActiveDefenseServiceRegistry::default();
        registry
            .reserve_exact(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));

        registry
            .commit_reserved_exact_with_release(&services, || handle.release_publication())
            .unwrap_or_else(|error| panic!("publish: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while worker.health().lifecycle != ResponseWorkerLifecycle::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("post-release worker crash was not observed"));

        assert!(registry.snapshot().is_some());
        assert!(services.ensure_ready().is_err());
        assert!(handle.shutdown().await.is_err());
        registry
            .unpublish_exact(&services)
            .unwrap_or_else(|error| panic!("unpublish failed services: {error}"));
    }

    #[tokio::test]
    async fn wedged_tick_fails_readiness_and_awaited_shutdown_never_drains_concurrently() {
        let port = Arc::new(BlockingWorkerPort::new());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        worker.configure_progress(Duration::from_millis(30));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tick did not start"));
        tokio::time::sleep(Duration::from_millis(40)).await;

        assert!(matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerProgressStalled { .. })
        ));
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
        assert!(worker.health().tick_in_flight);

        port.release();
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[tokio::test]
    async fn cancelled_shutdown_retains_join_until_the_blocked_tick_exits() {
        let port = Arc::new(BlockingWorkerPort::new());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tick did not start"));

        assert!(
            tokio::time::timeout(Duration::from_millis(20), handle.shutdown())
                .await
                .is_err()
        );
        assert!(worker.shutdown_requested.load(Ordering::Acquire));
        assert!(handle.join.is_some());
        assert!(port.tick_in_flight.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
        assert!(!worker.shutdown_is_complete());

        let mut resumed_shutdown = Box::pin(handle.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut resumed_shutdown)
                .await
                .is_err()
        );
        assert!(port.tick_in_flight.load(Ordering::Acquire));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
        assert!(!worker.shutdown_is_complete());
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .is_err());

        port.release();
        resumed_shutdown
            .as_mut()
            .await
            .unwrap_or_else(|error| panic!("resumed shutdown: {error}"));
        drop(resumed_shutdown);

        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
        assert!(worker.shutdown_is_complete());
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .unwrap_or_else(|_| panic!("worker did not publish clean shutdown completion"));
        assert!(handle.clean_shutdown);
        assert!(handle.join.is_none());
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[tokio::test]
    async fn dropping_handle_signals_stop_without_concurrent_drain_or_zombie_tick() {
        let port = Arc::new(BlockingWorkerPort::new());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tick did not start"));

        drop(handle);
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
        port.release();
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .unwrap_or_else(|_| panic!("worker did not stop"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !worker.thread_joined.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("dropped worker thread was not joined"));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[test]
    fn worker_crash_marks_health_failed_and_restart_can_take_over() {
        let failure = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.worker_crash")
                .unwrap_or_else(|error| panic!("error code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(failure),
            Ok(tick("action-after-crash")),
        ]));
        let crashed = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}"));
        assert!(crashed.tick_once().is_err());
        assert_eq!(crashed.health().lifecycle, ResponseWorkerLifecycle::Failed);

        let restarted = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("restart: {error}"));
        assert_eq!(
            restarted
                .tick_once()
                .unwrap_or_else(|error| panic!("takeover: {error}"))
                .completed_action_ids
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn terminated_primary_reuses_its_durable_port_without_concurrent_ticks() {
        let failure = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.primary_crash")
                .unwrap_or_else(|error| panic!("error code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(failure),
            Ok(tick("teardown-recovery")),
        ]));
        let primary = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("primary worker: {error}")),
        );
        let mut primary_handle = primary
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start primary: {error}"));
        primary_handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm primary: {error}"));
        primary_handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release primary: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while primary.health().lifecycle != ResponseWorkerLifecycle::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("primary did not fail"));
        assert!(primary_handle.shutdown().await.is_err());
        assert!(primary.shutdown_is_complete());

        let recovery = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("recovery worker: {error}")),
        );
        let mut recovery_handle = recovery
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start recovery: {error}"));
        recovery_handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm recovery: {error}"));
        recovery_handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release recovery: {error}"));
        recovery_handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("recovery publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while port.tick_calls() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("recovery worker did not tick"));
        recovery_handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown recovery: {error}"));

        assert_eq!(port.maximum_concurrent_ticks(), 1);
    }

    struct TestServices {
        ready: Mutex<bool>,
    }

    impl ActiveDefenseServices for TestServices {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            match self.ready.lock() {
                Ok(ready) if *ready => Ok(()),
                Ok(_) | Err(_) => Err(ResponseWorkerTickError::Port(PortError::unavailable())),
            }
        }

        fn worker_health(&self) -> ResponseWorkerHealth {
            ResponseWorkerHealth::created()
        }
    }

    struct SequencedServices {
        readiness: Mutex<VecDeque<bool>>,
    }

    impl ActiveDefenseServices for SequencedServices {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            match self.readiness.lock() {
                Ok(mut readiness) => match readiness.pop_front() {
                    Some(true) => Ok(()),
                    Some(false) | None => {
                        Err(ResponseWorkerTickError::Port(PortError::unavailable()))
                    }
                },
                Err(_) => Err(ResponseWorkerTickError::Port(PortError::unavailable())),
            }
        }

        fn worker_health(&self) -> ResponseWorkerHealth {
            ResponseWorkerHealth::created()
        }
    }

    struct BootstrapOnlyServices;

    impl ActiveDefenseServices for BootstrapOnlyServices {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            Err(ResponseWorkerTickError::Port(PortError::unavailable()))
        }

        fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
            Ok(())
        }

        fn worker_health(&self) -> ResponseWorkerHealth {
            ResponseWorkerHealth::created()
        }
    }

    #[test]
    fn service_publication_can_precede_operational_kernel_binding() {
        let registry = ActiveDefenseServiceRegistry::default();
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(BootstrapOnlyServices);
        registry
            .publish(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("publish bootstrap-ready services: {error}"));
        let installed = registry
            .snapshot()
            .unwrap_or_else(|| panic!("bootstrap-ready services are missing"));
        assert!(Arc::ptr_eq(&installed, &services));
        assert!(installed.ensure_ready().is_err());
    }

    #[test]
    fn service_publication_is_atomic_when_replacement_readiness_fails() {
        let registry = ActiveDefenseServiceRegistry::default();
        let first = Arc::new(TestServices {
            ready: Mutex::new(true),
        });
        let first_services: Arc<dyn ActiveDefenseServices> = first.clone();
        registry
            .publish(Arc::clone(&first_services))
            .unwrap_or_else(|error| panic!("publish first: {error}"));
        let replacement = Arc::new(TestServices {
            ready: Mutex::new(false),
        });
        assert!(registry.publish(replacement).is_err());
        let installed = registry
            .snapshot()
            .unwrap_or_else(|| panic!("installed services missing"));
        assert!(Arc::ptr_eq(&installed, &first_services));
    }

    #[test]
    fn service_publication_rechecks_readiness_at_commit_time() {
        let registry = ActiveDefenseServiceRegistry::default();
        let services = Arc::new(SequencedServices {
            readiness: Mutex::new(VecDeque::from([true, true, false])),
        });
        assert!(registry.publish(services).is_err());
        assert!(registry.snapshot().is_none());
    }

    #[test]
    fn service_publication_rejects_duplicate_ownership_without_replacement() {
        let registry = ActiveDefenseServiceRegistry::default();
        let first: Arc<dyn ActiveDefenseServices> = Arc::new(TestServices {
            ready: Mutex::new(true),
        });
        registry
            .publish(Arc::clone(&first))
            .unwrap_or_else(|error| panic!("publish first: {error}"));
        let duplicate: Arc<dyn ActiveDefenseServices> = Arc::new(TestServices {
            ready: Mutex::new(true),
        });

        assert!(matches!(
            registry.publish(duplicate),
            Err(ResponseWorkerTickError::ServicesAlreadyPublished)
        ));
        let installed = registry
            .snapshot()
            .unwrap_or_else(|| panic!("installed services missing"));
        assert!(Arc::ptr_eq(&installed, &first));
    }
