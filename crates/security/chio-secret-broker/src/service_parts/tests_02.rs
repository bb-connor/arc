    #[test]
    fn lost_prepare_response_capture_recovers_without_a_denial_terminal() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 45, 1);
        let ids = register_prepared_execution(&fixture, &request, &trusted, 30);
        let revocation_set = CanonicalBrokerRevocationSet::new(
            &request.capability.body.parent_capability_id,
            &["delegation-ancestor".to_string()],
            &request.capability.body.capability_id,
            &request.capability.body.revocation_id,
        )
        .test_expect("revocation set");
        fixture
            .authority
            .capture_execution_hold(&CaptureExecutionHoldRequest {
                operation_id: ids.operation_id.clone(),
                invocation_id: request.invocation_id.clone(),
                parent_capability_id: request.capability.body.parent_capability_id.clone(),
                broker_capability_id: request.capability.body.capability_id.clone(),
                hold_id: ids.hold_id.clone(),
                capture_event_id: ids.capture_event_id.clone(),
                revocation_ids: revocation_set.ids().to_vec(),
                revocation_set_digest: revocation_set.digest().to_string(),
                authorization_artifact_digest: capability_digest(&request.capability)
                    .test_expect("capability digest"),
                authority_metadata_digest: trusted.authority_metadata_digest.clone(),
            })
            .test_expect("capture committed before response loss");

        assert!(matches!(
            fixture.service.persist_admission_failure(
                &request,
                31,
                &BrokerError::AuthorityUnavailable("prepare response was lost".to_string()),
            ),
            Err(BrokerError::AuthorityUnavailable(_))
        ));
        let recovered = fixture
            .attempts
            .load_attempt(&ids.attempt_id)
            .test_expect("load recovered attempt")
            .test_expect("recovered attempt exists");
        assert_eq!(recovered.state, AttemptState::Captured);
        assert!(fixture
            .receipts
            .lock()
            .test_expect("receipt lock")
            .is_empty());

        assert!(matches!(
            fixture
                .service
                .execute_evidenced(&request, &trusted, 32)
                .test_expect("resume captured execution"),
            BrokerExecuteOutcome::Success(_)
        ));
        assert_eq!(
            fixture
                .observed_authorizations
                .lock()
                .test_expect("observed authorization lock")
                .len(),
            1
        );
    }

    #[test]
    fn exact_retry_resumes_prepared_held_or_captured_without_a_second_send() {
        for (invocation_index, recovered_state) in [
            (51, AttemptState::Prepared),
            (52, AttemptState::Held),
            (53, AttemptState::Captured),
        ] {
            let fixture = fixture(1, false, false);
            let (request, trusted) = execution(&fixture, invocation_index, 1);
            register_execution(&fixture, &request, &trusted, 20);
            let (ids, evidence) = captured_attempt_evidence(&fixture, &request, &trusted);
            if recovered_state == AttemptState::Held {
                fixture
                    .attempts
                    .transition(
                        &ids.attempt_id,
                        AttemptState::Prepared,
                        AttemptState::Held,
                        &AttemptTransitionEvidence::default(),
                        22,
                    )
                    .test_expect("journal held attempt");
            } else if recovered_state == AttemptState::Captured {
                fixture
                    .attempts
                    .transition(
                        &ids.attempt_id,
                        AttemptState::Prepared,
                        AttemptState::Captured,
                        &evidence,
                        22,
                    )
                    .test_expect("journal captured attempt");
            }

            let completed = fixture
                .service
                .execute(&request, &trusted, 23)
                .test_expect("resume exact pre-dispatch retry");
            assert_eq!(
                fixture
                    .observed_authorizations
                    .lock()
                    .test_expect("observed lock")
                    .len(),
                1
            );
            assert_eq!(
                fixture
                    .attempts
                    .load_attempt(&ids.attempt_id)
                    .test_expect("load completed attempt")
                    .test_expect("completed attempt")
                    .state,
                AttemptState::Completed
            );
            let receipt_count = fixture.receipts.lock().test_expect("receipt lock").len();
            let replayed = fixture
                .service
                .execute(&request, &trusted, 24)
                .test_expect("replay completed response");
            assert_eq!(replayed, completed);
            assert_eq!(
                fixture.receipts.lock().test_expect("receipt lock").len(),
                receipt_count,
                "completed retry must not emit another terminal receipt"
            );
            assert_eq!(
                fixture
                    .observed_authorizations
                    .lock()
                    .test_expect("observed lock")
                    .len(),
                1,
                "completed exact retry must not send again"
            );
        }
    }

    #[test]
    fn lost_completed_response_replays_exactly_after_service_and_store_restart() {
        let directory = crate::private_tempdir().test_expect("tempdir");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let attempt_path = trusted_directory.join("attempts.sqlite3");
        let receipt_path = trusted_directory.join("receipts.sqlite3");
        let receipt_signer = Keypair::from_seed(&[3; 32]);
        let attempts =
            Arc::new(SqliteAttemptStore::open(&attempt_path).test_expect("attempt store"));
        let receipt_sink = Arc::new(
            crate::receipt::SqliteBrokerReceiptSink::open(
                &receipt_path,
                receipt_signer.public_key(),
            )
            .test_expect("receipt sink"),
        );
        let fixture = fixture_with_stores(
            1,
            false,
            false,
            attempts,
            receipt_sink,
            Arc::new(Mutex::new(Vec::new())),
        );
        let (request, trusted) = execution(&fixture, 55, 1);
        register_execution(&fixture, &request, &trusted, 20);
        let completed = fixture
            .service
            .execute(&request, &trusted, 21)
            .test_expect("initial completed response");
        assert_eq!(
            fixture
                .observed_authorizations
                .lock()
                .test_expect("observed lock")
                .len(),
            1
        );

        let Fixture {
            service,
            issuer,
            backend,
            provider,
            https,
            authority,
            attempts,
            observed_authorizations,
            live_authority_calls,
            live_authority_unavailable,
            ..
        } = fixture;
        drop(service);
        drop(attempts);
        let reopened_attempts =
            Arc::new(SqliteAttemptStore::open(&attempt_path).test_expect("reopened attempt store"));
        let reopened_receipts = Arc::new(
            crate::receipt::SqliteBrokerReceiptSink::open(
                &receipt_path,
                receipt_signer.public_key(),
            )
            .test_expect("reopened receipt sink"),
        );
        let audit_authority_broker_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[71; 32])));
        let audit_authority_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[72; 32])));
        let restarted = BrokerService::new_production(
            BrokerServiceConfig {
                audience: "broker-service".to_string(),
                parent_audience: "broker-parent".to_string(),
                maximum_clock_skew_seconds: 2,
                maximum_liveness_snapshot_age_seconds: 5,
                maximum_revocation_snapshot_age_seconds: 5,
            },
            ProductionSqliteAttemptStore::new(reopened_attempts)
                .test_expect("production attempt store"),
            BrokerServiceAuthorityBundle {
                trusted_issuer: issuer.public_key(),
                backend,
                provider,
                https,
                budget: authority,
                liveness: Arc::new(LiveAuthority {
                    calls: Arc::clone(&live_authority_calls),
                    unavailable: Arc::clone(&live_authority_unavailable),
                    broker_signer: Arc::clone(&audit_authority_broker_signer),
                    authority_signer: Arc::clone(&audit_authority_signer),
                }),
                revocations: Arc::new(LiveRevocations {
                    calls: live_authority_calls,
                    unavailable: live_authority_unavailable,
                    broker_signer: audit_authority_broker_signer,
                    authority_signer: audit_authority_signer,
                }),
                receipt_sink: reopened_receipts,
                receipt_signer: Arc::new(Ed25519Backend::new(receipt_signer)),
                migration_enforcer: crate::migration::TestBrokerMigrationEnforcer::new(vec![
                    "generic-https".to_string(),
                ]),
            },
        )
        .test_expect("restarted service");

        let replayed = restarted
            .execute(&request, &trusted, 1_001)
            .test_expect("durable completed replay");
        assert_eq!(replayed, completed);
        assert_eq!(
            observed_authorizations
                .lock()
                .test_expect("observed lock")
                .len(),
            1,
            "completed replay must not redispatch"
        );
    }

    #[test]
    fn concurrent_captured_retries_have_one_dispatch_owner() {
        let fixture = Arc::new(fixture(1, false, false));
        let (request, trusted) = execution(&fixture, 54, 1);
        register_execution(&fixture, &request, &trusted, 20);
        let (ids, evidence) = captured_attempt_evidence(&fixture, &request, &trusted);
        fixture
            .attempts
            .transition(
                &ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::Captured,
                &evidence,
                22,
            )
            .test_expect("journal captured attempt");
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let fixture = Arc::clone(&fixture);
            let request = request.clone();
            let trusted = trusted.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                fixture.service.execute(&request, &trusted, 23)
            }));
        }
        let responses = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .test_expect("join retry worker")
                    .test_expect("captured retry succeeds")
            })
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0], responses[1]);
        assert_eq!(
            fixture
                .observed_authorizations
                .lock()
                .test_expect("observed lock")
                .len(),
            1
        );
    }

    #[test]
    fn dispatch_committed_and_unknown_retries_never_resend() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 55, 1);
        register_execution(&fixture, &request, &trusted, 20);
        let (ids, evidence) = captured_attempt_evidence(&fixture, &request, &trusted);
        fixture
            .attempts
            .transition(
                &ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::Captured,
                &evidence,
                22,
            )
            .test_expect("journal captured attempt");
        fixture
            .attempts
            .transition(
                &ids.attempt_id,
                AttemptState::Captured,
                AttemptState::DispatchCommitted,
                &evidence,
                23,
            )
            .test_expect("journal dispatch commitment");
        assert!(fixture.service.execute(&request, &trusted, 24).is_err());
        assert!(fixture.service.execute(&request, &trusted, 25).is_err());
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("observed lock")
            .is_empty());
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&ids.attempt_id)
                .test_expect("load unknown attempt")
                .test_expect("unknown attempt")
                .state,
            AttemptState::UnknownOutcome
        );
    }

    #[test]
    fn exactly_n_concurrent_requests_capture_and_only_upstream_sees_secret() {
        let maximum = 4;
        let fixture = Arc::new(fixture(maximum, false, false));
        let barrier = Arc::new(Barrier::new(12));
        let mut workers = Vec::new();
        for index in 0..12 {
            let fixture = Arc::clone(&fixture);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let (request, trusted) = execution(&fixture, index, maximum);
                register_execution(&fixture, &request, &trusted, 20);
                barrier.wait();
                fixture.service.execute(&request, &trusted, 21)
            }));
        }
        let responses = workers
            .into_iter()
            .filter_map(|worker| worker.join().test_expect("worker").ok())
            .collect::<Vec<_>>();
        assert_eq!(
            responses.len(),
            usize::try_from(maximum).test_expect("maximum")
        );
        assert_eq!(fixture.authority.captured_count(), responses.len());
        let observed = fixture
            .observed_authorizations
            .lock()
            .test_expect("observed lock");
        assert_eq!(observed.len(), responses.len());
        for value in observed.iter() {
            assert_eq!(
                value,
                &[b"Bearer ".as_slice(), fixture.canary.as_slice()].concat()
            );
        }
        for response in responses {
            let encoded = canonical_json_bytes(&response).test_expect("response");
            assert!(!encoded
                .windows(fixture.canary.len())
                .any(|window| window == fixture.canary.as_slice()));
        }
    }

    #[test]
    fn timeout_after_capture_consumes_quota_and_records_unknown_outcome() {
        let fixture = fixture(1, true, false);
        let (request, trusted) = execution(&fixture, 1, 1);
        register_execution(&fixture, &request, &trusted, 20);
        assert!(fixture.service.execute(&request, &trusted, 21).is_err());
        assert_eq!(fixture.authority.captured_count(), 1);
        let (second, trusted) = execution(&fixture, 2, 1);
        register_execution(&fixture, &second, &trusted, 20);
        assert!(fixture.service.execute(&second, &trusted, 21).is_err());
        assert_eq!(fixture.authority.captured_count(), 1);
    }

    #[test]
    fn completed_receipt_uses_post_dispatch_trusted_time() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 59, 1);
        register_execution(&fixture, &request, &trusted, 20);

        let outcome = fixture
            .service
            .execute_evidenced_with_terminal_clock(&request, &trusted, 21, &|| Ok(41))
            .test_expect("execute with terminal clock");
        let BrokerExecuteOutcome::Success(response) = outcome else {
            panic!("successful dispatch unexpectedly failed");
        };
        assert_eq!(response.receipt.body.issued_at_unix_seconds, 41);
    }

    #[test]
    fn failure_receipt_uses_post_dispatch_trusted_time() {
        let fixture = fixture(1, true, false);
        let (request, trusted) = execution(&fixture, 60, 1);
        register_execution(&fixture, &request, &trusted, 20);

        let outcome = fixture
            .service
            .execute_evidenced_with_terminal_clock(&request, &trusted, 21, &|| Ok(42))
            .test_expect("persist failure with terminal clock");
        let BrokerExecuteOutcome::Failure(failure) = outcome else {
            panic!("failed dispatch unexpectedly completed");
        };
        assert_eq!(failure.receipt.body.issued_at_unix_seconds, 42);
    }

    #[test]
    fn dispatch_transport_failure_is_terminal_unknown_and_exact_retry_never_resends() {
        let fixture = fixture(1, true, false);
        let (request, trusted) = execution(&fixture, 61, 1);
        register_execution(&fixture, &request, &trusted, 20);

        let first = fixture
            .service
            .execute_evidenced(&request, &trusted, 21)
            .test_expect("persist dispatch failure");
        let BrokerExecuteOutcome::Failure(failure) = &first else {
            panic!("dispatch failure unexpectedly completed");
        };
        let failure = failure.as_ref();
        assert_eq!(failure.receipt.body.stage, BrokerFailureStage::Dispatch);
        assert_eq!(failure.receipt.body.outcome, BrokerFailureOutcome::Unknown);
        assert_eq!(
            failure.receipt.body.dispatch_knowledge,
            BrokerDispatchKnowledge::Unknown
        );
        assert!(failure.receipt.body.attempt_id.is_some());
        let retry = fixture
            .service
            .execute_evidenced(&request, &trusted, 22)
            .test_expect("replay dispatch failure");
        assert_eq!(retry, first);
        assert_eq!(
            fixture
                .observed_authorizations
                .lock()
                .test_expect("observed lock")
                .len(),
            1,
            "terminal dispatch failure retry must not send again"
        );
    }

    #[test]
    fn response_signing_failure_is_committed_terminal_and_exact_retry_never_resends() {
        let attempts = Arc::new(SqliteAttemptStore::open_in_memory().test_expect("attempt store"));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let receipt_sink = Arc::new(InspectingReceiptSink {
            canary: b"unique-service-credential-canary".to_vec(),
            receipts: Arc::clone(&receipts),
            failures: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(BTreeMap::new()),
            failure_persist_entered: None,
            failure_persist_release: None,
            fail_completed: false,
        });
        let fixture = fixture_with_receipt_signer(
            FixtureServiceOptions {
                maximum_executions: 1,
                fail_transport: false,
                deny_capture: false,
                receipt_signer: Arc::new(FailFirstSigningBackend {
                    keypair: Keypair::from_seed(&[3; 32]),
                    fail_next: AtomicBool::new(true),
                }),
            },
            attempts,
            receipt_sink,
            receipts,
        );
        let (request, trusted) = execution(&fixture, 62, 1);
        register_execution(&fixture, &request, &trusted, 20);

        let first = fixture
            .service
            .execute_evidenced(&request, &trusted, 21)
            .test_expect("persist response-stage failure");
        let BrokerExecuteOutcome::Failure(failure) = &first else {
            panic!("signing failure unexpectedly completed");
        };
        let failure = failure.as_ref();
        assert_eq!(failure.receipt.body.stage, BrokerFailureStage::Response);
        assert_eq!(failure.receipt.body.outcome, BrokerFailureOutcome::Failed);
        assert_eq!(
            failure.receipt.body.dispatch_knowledge,
            BrokerDispatchKnowledge::Committed
        );
        assert_eq!(
            fixture
                .service
                .execute_evidenced(&request, &trusted, 22)
                .test_expect("replay response-stage failure"),
            first
        );
        assert_eq!(
            fixture
                .observed_authorizations
                .lock()
                .test_expect("observed lock")
                .len(),
            1
        );
    }

    #[test]
    fn completed_response_persistence_failure_has_distinct_committed_terminal() {
        let attempts = Arc::new(SqliteAttemptStore::open_in_memory().test_expect("attempt store"));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let receipt_sink = Arc::new(InspectingReceiptSink {
            canary: b"unique-service-credential-canary".to_vec(),
            receipts: Arc::clone(&receipts),
            failures: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(BTreeMap::new()),
            failure_persist_entered: None,
            failure_persist_release: None,
            fail_completed: true,
        });
        let fixture = fixture_with_stores(1, false, false, attempts, receipt_sink, receipts);
        let (request, trusted) = execution(&fixture, 63, 1);
        register_execution(&fixture, &request, &trusted, 20);

        let first = fixture
            .service
            .execute_evidenced(&request, &trusted, 21)
            .test_expect("persist completed-response storage failure");
        let BrokerExecuteOutcome::Failure(failure) = &first else {
            panic!("persistence failure unexpectedly completed");
        };
        let failure = failure.as_ref();
        assert_eq!(
            failure.receipt.body.stage,
            BrokerFailureStage::ReceiptPersistence
        );
        assert_eq!(failure.receipt.body.outcome, BrokerFailureOutcome::Failed);
        assert_eq!(
            failure.receipt.body.dispatch_knowledge,
            BrokerDispatchKnowledge::Committed
        );
        assert_eq!(
            fixture
                .service
                .execute_evidenced(&request, &trusted, 22)
                .test_expect("replay persistence failure"),
            first
        );
        assert_eq!(
            fixture
                .observed_authorizations
                .lock()
                .test_expect("observed lock")
                .len(),
            1
        );
    }

    #[test]
    fn denied_combined_capture_never_dispatches() {
        let fixture = fixture(1, false, true);
        let (request, trusted) = execution(&fixture, 1, 1);
        register_execution(&fixture, &request, &trusted, 20);
        assert!(fixture.service.execute(&request, &trusted, 21).is_err());
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("observed lock")
            .is_empty());
    }
