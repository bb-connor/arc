use super::*;


    #[test]
    fn startup_drain_does_not_confuse_deferred_backlog_with_empty_due_scan() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("deferred-startup.sqlite"))
                .unwrap_or_else(|error| panic!("deferred store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let pending = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load pending: {error}"))
            .unwrap_or_else(|| panic!("pending row missing"));
        store
            .transition_attested_finding_response_outbox(
                &pending,
                AttestedFindingResponseOutboxTransition::BeginAttempt {
                    next_attempt_at_unix_ms: 10_003,
                },
            )
            .unwrap_or_else(|error| panic!("stage abandoned claim: {error}"));
        let clock = Arc::new(MutableClock::new(10_002));
        let effects = Arc::new(AtomicUsize::new(0));
        let planner = recovery_planner(
            Arc::clone(&store),
            &findings,
            Arc::new(RecoveryPolicy {
                artifacts_unavailable: false,
            }),
            Arc::new(RecoveryCoordinator::new(
                false,
                false,
                Arc::clone(&effects),
            )),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let short = AttestedFindingResponseRecoveryLimits::new(1, 10, 1)
            .unwrap_or_else(|error| panic!("short limits: {error}"));
        assert!(planner.resume_incomplete_until_drained(short).is_err());
        assert!(planner
            .outbox_health()
            .is_ok_and(|health| health.planning_pending == 1));

        clock.set(10_004);
        let complete = AttestedFindingResponseRecoveryLimits::new(1, 10, 5_000)
            .unwrap_or_else(|error| panic!("complete limits: {error}"));
        planner
            .resume_incomplete_until_drained(complete)
            .unwrap_or_else(|error| panic!("drain abandoned claim: {error}"));
        assert_eq!(effects.load(Ordering::Acquire), 1);
    }
