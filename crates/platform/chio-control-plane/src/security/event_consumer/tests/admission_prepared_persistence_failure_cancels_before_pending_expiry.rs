use super::*;


        #[test]
    fn admission_prepared_persistence_failure_cancels_before_pending_expiry() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("cancel-before-expiry.sqlite"))
                .unwrap_or_else(|error| panic!("cancel-before-expiry store: {error}")),
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
                AdmissionPreparedFailureMode::BeforeWrite,
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
        .unwrap_or_else(|error| panic!("cancel-before-expiry planner: {error}"));

        planner
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("publish response plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load planned response: {error}"))
            .unwrap_or_else(|| panic!("planned response missing"));
        clock.set(planned.next_attempt_at_unix_ms.saturating_add(1));

        let error = rejected(
            planner.resume_incomplete_pass(1),
            "admission preparation persistence must fail",
        );
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
        assert_eq!(cancel_calls.load(Ordering::Acquire), 1);
        assert_eq!(effects.load(Ordering::Acquire), 0);
        let pending = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|load_error| panic!("load pending response: {load_error}"))
            .unwrap_or_else(|| panic!("pending response missing"));
        assert_eq!(
            pending.admission_state,
            AttestedFindingResponseAdmissionState::Pending
        );
        assert!(pending.prepared_dispatch_binding.is_none());

        let expires_at_unix_ms = pending
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("pending response publication missing"))
            .body
            .response_plan
            .expires_at_unix_ms;
        clock.set(expires_at_unix_ms);
        let expiry = rejected(
            planner.resume_incomplete_pass(1),
            "pending response must expire terminally",
        );
        assert_eq!(expiry.code().as_str(), "active_response.plan_expired");
        assert_eq!(cancel_calls.load(Ordering::Acquire), 1);
        assert_eq!(effects.load(Ordering::Acquire), 0);
    }
