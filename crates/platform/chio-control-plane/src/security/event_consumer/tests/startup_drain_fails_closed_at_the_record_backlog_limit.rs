use super::*;


    #[test]
    fn startup_drain_fails_closed_at_the_record_backlog_limit() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("bounded-startup.sqlite"))
                .unwrap_or_else(|error| panic!("bounded store: {error}")),
        );
        let findings = reverse_lexicographic_findings();
        publish_recovery_batch(store.as_ref(), &findings);
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
            Arc::new(FixedClock(10_002)),
        );
        let bounded = AttestedFindingResponseRecoveryLimits::new(1, 1, 100)
            .unwrap_or_else(|error| panic!("bounded limits: {error}"));
        assert!(planner.resume_incomplete_until_drained(bounded).is_err());
        let health = planner
            .outbox_health()
            .unwrap_or_else(|error| panic!("bounded health: {error}"));
        assert!(super::super::response_recovery_backlog(&health) > 0);

        let drain = AttestedFindingResponseRecoveryLimits::new(1, 10, 5_000)
            .unwrap_or_else(|error| panic!("drain limits: {error}"));
        planner
            .resume_incomplete_until_drained(drain)
            .unwrap_or_else(|error| panic!("bounded backlog drain: {error}"));
        assert_eq!(effects.load(Ordering::Acquire), 2);
    }
