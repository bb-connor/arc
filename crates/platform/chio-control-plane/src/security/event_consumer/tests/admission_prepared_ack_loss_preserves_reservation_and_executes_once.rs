use super::*;


    #[test]
    fn admission_prepared_ack_loss_preserves_reservation_and_executes_once() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("prepared-ack-loss.sqlite"))
                .unwrap_or_else(|error| panic!("prepared-ack-loss store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let clock = Arc::new(MutableClock::new(10_002));
        let effects = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let coordinator = Arc::new(
            RecoveryCoordinator::new(false, false, Arc::clone(&effects))
                .with_cancel_calls(Arc::clone(&cancel_calls)),
        );
        let outbox_store: Arc<dyn AttestedFindingResponseOutboxStore> = Arc::new(
            FailingAdmissionPreparedOutboxStore::new(
                Arc::clone(&store),
                AdmissionPreparedFailureMode::AfterWrite,
            ),
        );
        let planner = DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
            outbox_store,
            Arc::new(TestFindingAuthority::new(&findings)),
            Arc::new(GovernedRecoveryPolicy {
                artifacts_unavailable: false,
            }),
            coordinator,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("prepared-ack-loss planner: {error}"));

        planner
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("publish response plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load planned response: {error}"))
            .unwrap_or_else(|| panic!("planned response missing"));
        clock.set(planned.next_attempt_at_unix_ms.saturating_add(1));
        planner
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("recover prepared acknowledgement loss: {error}"));

        let completed = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load completed response: {error}"))
            .unwrap_or_else(|| panic!("completed response missing"));
        assert_eq!(
            completed.completion_state,
            AttestedFindingResponseCompletionState::Completed
        );
        assert_eq!(cancel_calls.load(Ordering::Acquire), 0);
        assert_eq!(effects.load(Ordering::Acquire), 1);
    }
