use super::*;

    #[test]
    fn prepared_crash_is_recovered_exactly_once_with_two_workers() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("two-workers.sqlite"))
                .unwrap_or_else(|error| panic!("two-worker store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let clock = Arc::new(MutableClock::new(10_002));
        let effects = Arc::new(AtomicUsize::new(0));
        let planner = Arc::new(recovery_planner(
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
        ));
        planner
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load planned: {error}"))
            .unwrap_or_else(|| panic!("planned row missing"));
        assert!(store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([0_u8; 32]),
                },
            )
            .is_err());
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind artifacts: {error}"));
        let mut zero_dispatch_binding = prepared_binding_for_outbox(
            &bound,
            RecordId::new(format!("valid-dispatch-{}", key.action_id.as_str()))
                .unwrap_or_else(|error| panic!("valid dispatch id: {error}")),
        );
        zero_dispatch_binding.dispatch_id = RecordId::new("0000")
            .unwrap_or_else(|error| panic!("zero dispatch id shape: {error}"));
        assert!(store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(zero_dispatch_binding),
                },
            )
            .is_err());
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("dispatch id: {error}"));
        let prepared_dispatch_binding = prepared_binding_for_outbox(&bound, dispatch_id);
        let prepared = store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
                },
            )
            .unwrap_or_else(|error| panic!("persist prepared crash boundary: {error}"));
        assert!(store
            .transition_attested_finding_response_outbox(
                &prepared,
                AttestedFindingResponseOutboxTransition::Completed {
                    execution_dispatch_id: prepared
                        .execution_dispatch_id
                        .clone()
                        .unwrap_or_else(|| panic!("prepared dispatch missing")),
                    outcome: AttestedFindingResponseCompletionOutcome::Activated,
                    evidence_id: OpaqueReceiptRef::new("zero-hash-evidence")
                        .unwrap_or_else(|error| panic!("zero evidence id: {error}")),
                    evidence_body_hash: Digest32::new([0_u8; 32]),
                },
            )
            .is_err());

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let planner = Arc::clone(&planner);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                planner.resume_incomplete_pass(1)
            }));
        }
        barrier.wait();
        for worker in workers {
            worker
                .join()
                .unwrap_or_else(|_| panic!("recovery worker panicked"))
                .unwrap_or_else(|error| panic!("recovery worker failed: {error}"));
        }
        let completed = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("two-worker completion: {error}"))
            .unwrap_or_else(|| panic!("two-worker row missing"));
        assert_eq!(completed.completion_state, AttestedFindingResponseCompletionState::Completed);
        assert_eq!(effects.load(Ordering::Acquire), 1);
    }
