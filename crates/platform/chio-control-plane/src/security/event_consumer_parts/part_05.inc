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
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
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
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
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
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
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
                Arc::clone(&clock) as Arc<dyn SecurityClock>,
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

    #[test]
    fn committed_dispatch_recovers_before_mutable_finding_policy_or_live_readiness() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("committed-recovery.sqlite"))
                .unwrap_or_else(|error| panic!("committed recovery store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let effects = Arc::new(AtomicUsize::new(0));
        let initial = recovery_planner(
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
        initial
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime committed recovery plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load committed recovery plan: {error}"))
            .unwrap_or_else(|| panic!("committed recovery plan missing"));
        let response_plan = planned
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("committed recovery publication missing"))
            .body
            .response_plan
            .clone();
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind committed recovery artifacts: {error}"));
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("committed recovery dispatch id: {error}"));
        let prepared_dispatch_binding =
            prepared_binding_for_outbox(&bound, dispatch_id.clone());
        store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
                },
            )
            .unwrap_or_else(|error| panic!("stage committed recovery dispatch: {error}"));

        let recovery_calls = Arc::new(AtomicUsize::new(0));
        let proof = AttestedFindingResponseCompletionProof::synthetic(
            dispatch_id.clone(),
            AttestedFindingResponseCompletionOutcome::Activated,
            OpaqueReceiptRef::new("committed-recovery-evidence")
                .unwrap_or_else(|error| panic!("committed recovery evidence id: {error}")),
            Digest32::new([76_u8; 32]),
        );
        let restarted = recovery_planner(
            Arc::clone(&store),
            &[],
            Arc::new(RecoveryPolicy {
                artifacts_unavailable: true,
            }),
            Arc::new(RecoveryCoordinator::committed(
                response_plan.plan_hash,
                proof,
                Arc::clone(&recovery_calls),
                Arc::clone(&effects),
            )),
            Arc::new(FixedClock(10_002)),
        );
        restarted
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("recover committed dispatch: {error}"));

        let completed = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load committed recovery result: {error}"))
            .unwrap_or_else(|| panic!("committed recovery result missing"));
        assert_eq!(completed.completion_state, AttestedFindingResponseCompletionState::Completed);
        assert_eq!(completed.execution_dispatch_id, Some(dispatch_id));
        assert_eq!(recovery_calls.load(Ordering::Acquire), 1);
        assert_eq!(effects.load(Ordering::Acquire), 0);
    }

    #[test]
    fn operation_committed_dispatch_resumes_after_executor_readback_is_missing() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("operation-committed.sqlite"))
                .unwrap_or_else(|error| panic!("operation committed store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let effects = Arc::new(AtomicUsize::new(0));
        let initial = recovery_planner(
            Arc::clone(&store),
            &findings,
            Arc::new(GovernedRecoveryPolicy {
                artifacts_unavailable: false,
            }),
            Arc::new(RecoveryCoordinator::new(
                false,
                false,
                Arc::clone(&effects),
            )),
            Arc::new(FixedClock(10_002)),
        );
        initial
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime operation committed plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load operation committed plan: {error}"))
            .unwrap_or_else(|| panic!("operation committed plan missing"));
        let response_plan = planned
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("operation committed publication missing"))
            .body
            .response_plan
            .clone();
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind operation committed artifacts: {error}"));
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("operation committed dispatch id: {error}"));
        let prepared_dispatch_binding =
            prepared_binding_for_outbox(&bound, dispatch_id.clone());
        store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
                },
            )
            .unwrap_or_else(|error| panic!("stage operation committed dispatch: {error}"));

        let resume_calls = Arc::new(AtomicUsize::new(0));
        let proof = AttestedFindingResponseCompletionProof::synthetic(
            dispatch_id.clone(),
            AttestedFindingResponseCompletionOutcome::FailedBeforeEffect,
            OpaqueReceiptRef::new("operation-committed-terminal-evidence")
                .unwrap_or_else(|error| panic!("operation committed evidence id: {error}")),
            Digest32::new([77_u8; 32]),
        );
        let restarted = recovery_planner(
            Arc::clone(&store),
            &[],
            Arc::new(GovernedRecoveryPolicy {
                artifacts_unavailable: true,
            }),
            Arc::new(RecoveryCoordinator::dispatch_committed(
                response_plan.plan_hash,
                proof,
                Arc::clone(&resume_calls),
                Arc::clone(&effects),
            )),
            Arc::new(FixedClock(10_002)),
        );
        restarted
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("resume operation committed dispatch: {error}"));

        let completed = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load operation committed result: {error}"))
            .unwrap_or_else(|| panic!("operation committed result missing"));
        assert_eq!(completed.completion_state, AttestedFindingResponseCompletionState::Completed);
        assert_eq!(completed.execution_dispatch_id, Some(dispatch_id));
        assert_eq!(
            completed.completion_outcome,
            Some(AttestedFindingResponseCompletionOutcome::FailedBeforeEffect)
        );
        assert_eq!(resume_calls.load(Ordering::Acquire), 1);
        assert_eq!(effects.load(Ordering::Acquire), 0);
    }

    #[test]
    fn rewritten_prepared_binding_resume_failure_stays_outcome_unknown() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("rewritten-binding.sqlite"))
                .unwrap_or_else(|error| panic!("rewritten binding store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let effects = Arc::new(AtomicUsize::new(0));
        let initial = recovery_planner(
            Arc::clone(&store),
            &findings,
            Arc::new(GovernedRecoveryPolicy {
                artifacts_unavailable: false,
            }),
            Arc::new(RecoveryCoordinator::new(
                false,
                false,
                Arc::clone(&effects),
            )),
            Arc::new(FixedClock(10_002)),
        );
        initial
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime rewritten binding plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load rewritten binding plan: {error}"))
            .unwrap_or_else(|| panic!("rewritten binding plan missing"));
        let expires_at_unix_ms = planned
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("rewritten binding publication missing"))
            .body
            .response_plan
            .expires_at_unix_ms;
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind rewritten artifacts: {error}"));
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("rewritten dispatch id: {error}"));
        let mut rewritten = prepared_binding_for_outbox(&bound, dispatch_id.clone());
        rewritten.governed_intent_hash = Digest32::new([88_u8; 32]);
        rewritten.policy_decision_hash = Digest32::new([89_u8; 32]);
        store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(rewritten.clone()),
                },
            )
            .unwrap_or_else(|error| panic!("stage rewritten prepared binding: {error}"));

        let resume_calls = Arc::new(AtomicUsize::new(0));
        let termination_calls = Arc::new(AtomicUsize::new(0));
        let restarted = recovery_planner(
            Arc::clone(&store),
            &[],
            Arc::new(GovernedRecoveryPolicy {
                artifacts_unavailable: true,
            }),
            Arc::new(RecoveryCoordinator::resume_integrity_failure(
                Arc::clone(&resume_calls),
                Arc::clone(&termination_calls),
                Arc::clone(&effects),
            )),
            Arc::new(FixedClock(expires_at_unix_ms)),
        );
        let error = rejected(
            restarted.resume_incomplete_pass(1),
            "rewritten operation anchor must fail closed",
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);

        let retained = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load rewritten binding result: {error}"))
            .unwrap_or_else(|| panic!("rewritten binding result missing"));
        assert_eq!(retained.admission_state, AttestedFindingResponseAdmissionState::Prepared);
        assert_eq!(
            retained.completion_state,
            AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
        );
        assert_eq!(retained.prepared_dispatch_binding, Some(rewritten));
        assert!(!retained.is_complete());
        assert_eq!(resume_calls.load(Ordering::Acquire), 1);
        assert_eq!(termination_calls.load(Ordering::Acquire), 0);
        assert_eq!(effects.load(Ordering::Acquire), 0);
    }

    #[test]
    fn authoritative_never_committed_probe_closes_prepared_dispatch_terminally() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("never-committed.sqlite"))
                .unwrap_or_else(|error| panic!("never-committed store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let clock = Arc::new(MutableClock::new(10_002));
        let effects = Arc::new(AtomicUsize::new(0));
        let termination_calls = Arc::new(AtomicUsize::new(0));
        let planner = recovery_planner(
            Arc::clone(&store),
            &findings,
            Arc::new(RecoveryPolicy {
                artifacts_unavailable: false,
            }),
            Arc::new(RecoveryCoordinator::never_committed(
                Arc::clone(&effects),
                Arc::clone(&termination_calls),
            )),
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
        );
        planner
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime never-committed plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load never-committed plan: {error}"))
            .unwrap_or_else(|| panic!("never-committed plan missing"));
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind never-committed artifacts: {error}"));
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("never-committed dispatch id: {error}"));
        let prepared_dispatch_binding =
            prepared_binding_for_outbox(&bound, dispatch_id.clone());
        store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
                },
            )
            .unwrap_or_else(|error| panic!("stage never-committed prepared row: {error}"));
        let error = rejected(
            planner.resume_incomplete_pass(1),
            "authoritative never-committed proof must close with its terminal error",
        );
        assert_eq!(error.code().as_str(), "active_response.never_committed");
        let terminal = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load never-committed terminal row: {error}"))
            .unwrap_or_else(|| panic!("never-committed terminal row missing"));
        assert_eq!(terminal.admission_state, AttestedFindingResponseAdmissionState::Expired);
        assert_eq!(terminal.execution_dispatch_id, Some(dispatch_id));
        assert_eq!(terminal.completion_state, AttestedFindingResponseCompletionState::NotStarted);
        assert!(terminal.is_complete());
        assert_eq!(effects.load(Ordering::Acquire), 0);
        assert_eq!(termination_calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn expired_prepared_dispatch_terminates_without_mutable_live_dependencies() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("expired-prepared.sqlite"))
                .unwrap_or_else(|error| panic!("expired prepared store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let effects = Arc::new(AtomicUsize::new(0));
        let initial = recovery_planner(
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
        initial
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("prime expired prepared plan: {error}"));
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load expired prepared plan: {error}"))
            .unwrap_or_else(|| panic!("expired prepared plan missing"));
        let expires_at_unix_ms = planned
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("expired prepared publication missing"))
            .body
            .response_plan
            .expires_at_unix_ms;
        let bound = store
            .transition_attested_finding_response_outbox(
                &planned,
                AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                    artifact_digest: Digest32::new([74_u8; 32]),
                },
            )
            .unwrap_or_else(|error| panic!("bind expired prepared artifacts: {error}"));
        let dispatch_id = RecordId::new(format!(
            "recovery-dispatch-{}",
            key.action_id.as_str()
        ))
        .unwrap_or_else(|error| panic!("expired prepared dispatch id: {error}"));
        let prepared_dispatch_binding =
            prepared_binding_for_outbox(&bound, dispatch_id.clone());
        store
            .transition_attested_finding_response_outbox(
                &bound,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                    prepared_dispatch_binding: Box::new(prepared_dispatch_binding.clone()),
                },
            )
            .unwrap_or_else(|error| panic!("stage expired prepared dispatch: {error}"));

        let termination_calls = Arc::new(AtomicUsize::new(0));
        let restarted = recovery_planner(
            Arc::clone(&store),
            &[],
            Arc::new(RecoveryPolicy {
                artifacts_unavailable: true,
            }),
            Arc::new(RecoveryCoordinator::expired_never_committed(
                Arc::clone(&effects),
                Arc::clone(&termination_calls),
            )),
            Arc::new(FixedClock(expires_at_unix_ms)),
        );
        let error = rejected(
            restarted.resume_incomplete_pass(1),
            "expired prepared dispatch must close with its typed terminal error",
        );
        assert_eq!(error.code().as_str(), "active_response.never_committed");

        let terminal = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("load expired prepared result: {error}"))
            .unwrap_or_else(|| panic!("expired prepared result missing"));
        assert_eq!(terminal.admission_state, AttestedFindingResponseAdmissionState::Expired);
        assert_eq!(terminal.execution_dispatch_id, Some(dispatch_id));
        assert_eq!(
            terminal.prepared_dispatch_binding,
            Some(prepared_dispatch_binding)
        );
        assert_eq!(terminal.completion_state, AttestedFindingResponseCompletionState::NotStarted);
        assert_eq!(termination_calls.load(Ordering::Acquire), 1);
        assert_eq!(effects.load(Ordering::Acquire), 0);
    }

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
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
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
        assert!(super::response_recovery_backlog(&health) > 0);

        let drain = AttestedFindingResponseRecoveryLimits::new(1, 10, 5_000)
            .unwrap_or_else(|error| panic!("drain limits: {error}"));
        planner
            .resume_incomplete_until_drained(drain)
            .unwrap_or_else(|error| panic!("bounded backlog drain: {error}"));
        assert_eq!(effects.load(Ordering::Acquire), 2);
    }

    #[test]
    fn planner_api_accepts_only_authoritative_signed_finding_evidence() {
        fn assert_planner_contract<T: AttestedFindingBatchPlanner>() {}
        assert_planner_contract::<RecordingPlanner>();
    }
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
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
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

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/event_consumer_parts/part_06.inc"
    ));
