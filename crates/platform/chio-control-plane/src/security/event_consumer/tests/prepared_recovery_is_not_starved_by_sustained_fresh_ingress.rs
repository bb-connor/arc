use super::*;


    #[test]
    fn prepared_recovery_is_not_starved_by_sustained_fresh_ingress() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("recovery-fairness.sqlite"))
                .unwrap_or_else(|error| panic!("fairness store: {error}")),
        );
        let mut findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let effects = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(FixedClock(10_002));
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
        planner
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime fairness plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load fairness plan: {error}"))
            .unwrap_or_else(|| panic!("fairness plan missing"));
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind fairness artifacts: {error}"));
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("fairness dispatch id: {error}"));
        let prepared_dispatch_binding =
            prepared_binding_for_outbox(&bound, dispatch_id);
        store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
                },
            )
            .unwrap_or_else(|error| panic!("stage fairness prepared row: {error}"));

        let mut completed_on_pass = None;
        for pass in 0_u8..3 {
            let finding_id = format!("finding-ingress-{pass}");
            let rule_id = format!("rule-ingress-{pass}");
            let incoming = authoritative_finding_with_identity(
                &finding_id,
                &rule_id,
                80_u8.saturating_add(pass),
            );
            publish_recovery_batch(store.as_ref(), std::slice::from_ref(&incoming));
            findings.push(incoming);
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
            planner
                .resume_incomplete_pass(1)
                .unwrap_or_else(|error| panic!("fairness pass {pass}: {error}"));
            let original = store
                .load_attested_finding_response_outbox(&key)
                .unwrap_or_else(|error| panic!("load fairness result: {error}"))
                .unwrap_or_else(|| panic!("fairness result missing"));
            if completed_on_pass.is_none()
                && original.completion_state
                    == AttestedFindingResponseCompletionState::Completed
            {
                completed_on_pass = Some(pass.saturating_add(1));
            }
        }

        assert_eq!(completed_on_pass, Some(1));
        assert!(effects.load(Ordering::Acquire) >= 1);
    }
