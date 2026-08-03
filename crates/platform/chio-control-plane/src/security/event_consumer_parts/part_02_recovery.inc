    #[test]
    fn correlation_ingress_ack_loss_keeps_the_durable_tombstone_and_does_not_republish() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("correlation-ack-loss.sqlite"))
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let keypair = Keypair::from_seed(&[94_u8; 32]);
        let event = signed_event_kind(
            "native-ack-loss",
            SecurityEventKind::CanaryInvocation,
            &keypair,
        );
        let ingress = VerifiedSecurityEventIngress::new(
            Arc::new(verifier(&keypair)),
            Arc::clone(&store),
        )
        .unwrap_or_else(|error| panic!("ingress: {error}"));
        ingress
            .verify_and_append(&event)
            .unwrap_or_else(|error| panic!("enqueue native event: {error}"));

        let planner = durable_test_planner(&store);
        let consumer = correlation_consumer(
            &keypair,
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        );
        let faulting_store: Arc<dyn CorrelationIngressStore> =
            Arc::new(AckLossCorrelationIngressStore {
                inner: Arc::clone(&store),
                lose_ack: AtomicBool::new(true),
            });
        let drainer = DurableCorrelationIngress::new(faulting_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));
        assert!(drainer.drain_once(16).is_err());
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after ack loss: {error}")),
            0
        );
        assert_eq!(
            Connection::open(directory.path().join("correlation-ack-loss.sqlite"))
                .and_then(|connection| connection.query_row(
                    "SELECT COUNT(*) FROM security_attested_finding_batches",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap_or_else(|error| panic!("count batches after ack loss: {error}")),
            1_i64
        );
        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("retry after ack loss: {error}")),
            0
        );
        assert_eq!(
            Connection::open(directory.path().join("correlation-ack-loss.sqlite"))
                .and_then(|connection| connection.query_row(
                    "SELECT COUNT(*) FROM security_attested_finding_response_outbox",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap_or_else(|error| panic!("count response work after ack loss: {error}")),
            1_i64
        );
    }
    #[test]
    fn response_publication_ack_loss_retries_without_duplicate_batch_or_outbox_work() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("response-publication-ack-loss.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let keypair = Keypair::from_seed(&[96_u8; 32]);
        let event = signed_event_kind(
            "native-response-publication-ack-loss",
            SecurityEventKind::WatermarkObservation,
            &keypair,
        );
        let ingress = VerifiedSecurityEventIngress::new(
            Arc::new(verifier(&keypair)),
            Arc::clone(&store),
        )
        .unwrap_or_else(|error| panic!("ingress: {error}"));
        ingress
            .verify_and_append(&event)
            .unwrap_or_else(|error| panic!("enqueue native event: {error}"));

        let durable_planner = durable_test_planner(&store);
        let faulting_planner: Arc<dyn AttestedFindingBatchPlanner> =
            Arc::new(AckLossAttestedFindingBatchPlanner {
                inner: Arc::clone(&durable_planner) as Arc<dyn AttestedFindingBatchPlanner>,
                lose_publish_ack: AtomicBool::new(true),
            });
        let consumer = correlation_consumer(&keypair, faulting_planner);
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));

        assert!(drainer.drain_once(16).is_err());
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after publication ack loss: {error}")),
            1
        );
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect publication ack loss: {error}"));
        for table in [
            "security_attested_finding_batches",
            "security_attested_finding_response_outbox",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(count, 1, "publication did not commit exactly once for {table}");
        }

        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("retry publication: {error}")),
            1
        );
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after publication retry: {error}")),
            0
        );
        for table in [
            "security_attested_finding_batches",
            "security_attested_finding_response_outbox",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("recount {table}: {error}"));
            assert_eq!(count, 1, "retry duplicated durable work for {table}");
        }
    }

    #[test]
    fn attestation_failure_leaves_ingress_pending_until_response_work_is_durable() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("attestation-retry.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let keypair = Keypair::from_seed(&[97_u8; 32]);
        let event = signed_event_kind(
            "native-attestation-retry",
            SecurityEventKind::TripwireObservation,
            &keypair,
        );
        let ingress = VerifiedSecurityEventIngress::new(
            Arc::new(verifier(&keypair)),
            Arc::clone(&store),
        )
        .unwrap_or_else(|error| panic!("ingress: {error}"));
        ingress
            .verify_and_append(&event)
            .unwrap_or_else(|error| panic!("enqueue native event: {error}"));

        let planner = durable_test_planner(&store);
        let consumer = Arc::new(
            ProductionCorrelationConsumer::from_parts(
                Arc::new(verifier(&keypair)),
                Arc::new(OneFindingCorrelation),
                Arc::new(FailOnceAttestor {
                    fail: AtomicBool::new(true),
                }),
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            )
            .unwrap_or_else(|error| panic!("consumer: {error}")),
        );
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));

        assert!(drainer.drain_once(16).is_err());
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after attestation failure: {error}")),
            1
        );
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect attestation failure: {error}"));
        for table in [
            "security_attested_finding_batches",
            "security_attested_finding_response_outbox",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(count, 0, "attestation failure leaked work into {table}");
        }

        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("retry attestation: {error}")),
            1
        );
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after attestation retry: {error}")),
            0
        );
        for table in [
            "security_attested_finding_batches",
            "security_attested_finding_response_outbox",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("recount {table}: {error}"));
            assert_eq!(count, 1, "attestation retry duplicated {table}");
        }
    }

    #[test]
    fn synchronous_consume_persists_ingress_before_downstream_failure() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("synchronous-consume-crash.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let keypair = Keypair::from_seed(&[99_u8; 32]);
        let event = signed_event_kind(
            "synchronous-consume-crash",
            SecurityEventKind::TripwireObservation,
            &keypair,
        );
        let planner = durable_test_planner(&store);
        let consumer = Arc::new(
            ProductionCorrelationConsumer::from_parts(
                Arc::new(verifier(&keypair)),
                Arc::new(OneFindingCorrelation),
                Arc::new(FailOnceAttestor {
                    fail: AtomicBool::new(true),
                }),
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            )
            .unwrap_or_else(|error| panic!("consumer: {error}")),
        );
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let durable_ingress = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress: {error}"));

        assert!(durable_ingress.consume(&event).is_err());
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after synchronous failure: {error}")),
            1
        );
        assert_eq!(
            durable_ingress
                .drain_once(16)
                .unwrap_or_else(|error| panic!("recover synchronous consume: {error}")),
            1
        );
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after recovery: {error}")),
            0
        );
        let connection = Connection::open(path)
            .unwrap_or_else(|error| panic!("inspect synchronous recovery: {error}"));
        for table in [
            "security_attested_finding_batches",
            "security_attested_finding_response_outbox",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(count, 1, "recovery did not commit exactly one {table} row");
        }
    }

    struct ReverseLexicographicAttestor;

    impl CorrelationAttestor for ReverseLexicographicAttestor {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn attest(
            &self,
            _: &CorrelationOutcome,
        ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
            Ok(reverse_lexicographic_findings())
        }
    }

    #[derive(Default)]
    struct DropAllPlanner {
        published: AtomicBool,
    }

    impl AttestedFindingBatchPlanner for DropAllPlanner {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn publish_attested_batch(
            &self,
            _: &[AuthoritativeCorrelatedFindingEvidence],
        ) -> PortResult<()> {
            self.published.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum ReadbackMutation {
        Reverse,
        DropLast,
    }

    struct MutatingReadbackPlanner {
        publication: Mutex<Option<AttestedFindingBatchPublication>>,
        mutation: ReadbackMutation,
    }

    impl MutatingReadbackPlanner {
        fn new(mutation: ReadbackMutation) -> Self {
            Self {
                publication: Mutex::new(None),
                mutation,
            }
        }
    }

    impl AttestedFindingBatchPlanner for MutatingReadbackPlanner {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn publish_attested_batch(
            &self,
            findings: &[AuthoritativeCorrelatedFindingEvidence],
        ) -> PortResult<()> {
            let publication = build_attested_finding_batch_publication(findings)?;
            *self
                .publication
                .lock()
                .map_err(|_| PortError::unavailable())? = Some(publication);
            Ok(())
        }

        fn load_published_attested_batch(
            &self,
            _: &AttestedFindingBatchKey,
        ) -> PortResult<AttestedFindingBatchPublication> {
            let mut publication = self
                .publication
                .lock()
                .map_err(|_| PortError::unavailable())?
                .clone()
                .ok_or_else(PortError::integrity_failure)?;
            let mut bindings = publication.body.bindings.clone().into_vec();
            match self.mutation {
                ReadbackMutation::Reverse => bindings.reverse(),
                ReadbackMutation::DropLast => {
                    bindings.pop();
                }
            }
            publication.body.bindings = AttestedFindingBatchBindings::new(bindings)
                .map_err(|_| PortError::integrity_failure())?;
            Ok(publication)
        }
    }

    #[test]
    fn production_consumer_rejects_drop_all_planner_without_read_after_write_proof() {
        let keypair = Keypair::from_seed(&[83_u8; 32]);
        let planner = Arc::new(DropAllPlanner::default());
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(OneFindingCorrelation),
            Arc::new(OneFindingAttestor),
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        let error = rejected(
            consumer.consume(&signed_event(&keypair)),
            "drop-all planner must fail read-after-write verification",
        );
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );
        assert!(planner.published.load(Ordering::Acquire));
    }

    #[test]
    fn production_consumer_accepts_and_reports_the_exact_persisted_finding_batch() {
        let keypair = Keypair::from_seed(&[84_u8; 32]);
        let planner = Arc::new(RecordingPlanner::default());
        let expected_id = authoritative_finding().evidence_id().clone();
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(OneFindingCorrelation),
            Arc::new(OneFindingAttestor),
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        let report = consumer
            .consume(&signed_event(&keypair))
            .unwrap_or_else(|error| panic!("persisted planner batch rejected: {error}"));
        assert_eq!(report.attested_finding_ids, vec![expected_id.clone()]);
        let batches = planner
            .batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(batches.len(), 1);
        assert_eq!(
            batches[0].body.bindings.as_slice()[0].evidence_id,
            expected_id
        );
    }

    #[test]
    fn production_consumer_preserves_the_exact_persisted_finding_order() {
        let keypair = Keypair::from_seed(&[85_u8; 32]);
        let planner = Arc::new(RecordingPlanner::default());
        let expected = reverse_lexicographic_findings()
            .into_iter()
            .map(|finding| finding.evidence_id().clone())
            .collect::<Vec<_>>();
        assert!(expected[0] > expected[1]);
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(OneFindingCorrelation),
            Arc::new(ReverseLexicographicAttestor),
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        let report = consumer
            .consume(&signed_event(&keypair))
            .unwrap_or_else(|error| panic!("persisted planner order rejected: {error}"));
        assert_eq!(report.attested_finding_ids, expected);
    }

    #[test]
    fn durable_production_planner_reloads_the_exact_batch_after_restart() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("durable-planner.sqlite");
        let findings = reverse_lexicographic_findings();
        let expected = build_attested_finding_batch_publication(&findings)
            .unwrap_or_else(|error| panic!("expected publication: {error}"));
        let policy = Arc::new(RecordingResponsePolicy);
        let coordinator = Arc::new(RecordingResponseCoordinator::default());
        {
            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("open durable planner store: {error}")),
            );
            let planner = DurableAttestedFindingBatchPlanner::new(
                Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
                store as Arc<dyn AttestedFindingResponseOutboxStore>,
                Arc::new(TestFindingAuthority::new(&findings)),
                Arc::clone(&policy) as Arc<dyn AttestedFindingResponsePolicyPlanner>,
                Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
                Arc::new(FixedClock(10_002)),
            )
            .unwrap_or_else(|error| panic!("durable planner: {error}"));
            planner
                .publish_attested_batch(&findings)
                .unwrap_or_else(|error| panic!("publish batch: {error}"));
            planner
                .publish_attested_batch(&findings)
                .unwrap_or_else(|error| panic!("retry batch: {error}"));
        }
        let reopened_store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("reopen durable planner store: {error}")),
        );
        let reopened = DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&reopened_store) as Arc<dyn AttestedFindingBatchStore>,
            reopened_store as Arc<dyn AttestedFindingResponseOutboxStore>,
            Arc::new(TestFindingAuthority::new(&findings)),
            Arc::clone(&policy) as Arc<dyn AttestedFindingResponsePolicyPlanner>,
            Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
            Arc::new(FixedClock(10_002)),
        )
        .unwrap_or_else(|error| panic!("reopened durable planner: {error}"));
        assert_eq!(
            reopened
                .load_published_attested_batch(&AttestedFindingBatchKey {
                    tenant_id: expected.body.tenant_id.clone(),
                    batch_id: expected.body.batch_id.clone(),
                })
                .unwrap_or_else(|error| panic!("reload publication: {error}")),
            expected
        );
        let executions = coordinator
            .executions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(executions.len(), 2);
    }

    #[test]
    fn durable_production_planner_cannot_report_success_without_admission_artifacts() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("missing-admission.sqlite"))
                .unwrap_or_else(|error| panic!("admission store: {error}")),
        );
        let coordinator = Arc::new(ArtifactEnforcingCoordinator::default());
        let planner = DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&store)
                as Arc<dyn chio_security_types::ports::AttestedFindingBatchStore>,
            store as Arc<dyn AttestedFindingResponseOutboxStore>,
            Arc::new(TestFindingAuthority::new(std::slice::from_ref(
                &authoritative_finding(),
            ))),
            Arc::new(MissingArtifactResponsePolicy),
            Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
            Arc::new(FixedClock(10_002)),
        )
        .unwrap_or_else(|error| panic!("durable planner: {error}"));
        let finding = authoritative_finding();
        let expected = build_attested_finding_batch_publication(std::slice::from_ref(&finding))
            .unwrap_or_else(|error| panic!("expected publication: {error}"));
        let error = rejected(
            planner.publish_attested_batch(std::slice::from_ref(&finding)),
            "missing capability and approval artifacts must fail closed",
        );
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );
        let replay_error = rejected(
            planner.publish_attested_batch(std::slice::from_ref(&finding)),
            "a durable terminal response failure must replay as failure",
        );
        assert_eq!(replay_error.code(), error.code());
        assert!(!coordinator.effects_applied.load(Ordering::Acquire));
        assert_eq!(
            planner
                .load_published_attested_batch(&AttestedFindingBatchKey {
                    tenant_id: expected.body.tenant_id.clone(),
                    batch_id: expected.body.batch_id.clone(),
                })
                .unwrap_or_else(|error| panic!("dry-run batch: {error}")),
            expected
        );
    }

    #[test]
    fn production_response_coordinator_rejects_a_kernel_without_governed_runtime() {
        let kernel = Arc::new(chio_kernel::ChioKernel::new(chio_kernel::KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "ungoverned-response-test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        }));
        let executor = chio_kernel::ActiveResponseExecutorAuthorityIdentity::new(
            Keypair::from_seed(&[92_u8; 32]).public_key(),
            1,
        )
        .unwrap_or_else(|error| panic!("executor identity: {error}"));
        let coordinator = KernelAttestedFindingResponseCoordinator::new_unbound(
            executor,
            Arc::new(FixedClock(1)),
        );
        let unbound = rejected(
            coordinator.ensure_ready(),
            "an unbound response coordinator must not report ready",
        );
        assert_eq!(
            unbound.kind(),
            chio_security_types::ports::PortErrorKind::Unavailable
        );
        let error = match coordinator.bind_kernel(kernel) {
            Ok(()) => panic!("a kernel without the atomic governed runtime was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::Unavailable
        );
    }

    #[test]
    fn production_consumer_rejects_reordered_durable_response_bindings() {
        let keypair = Keypair::from_seed(&[86_u8; 32]);
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(OneFindingCorrelation),
            Arc::new(ReverseLexicographicAttestor),
            Arc::new(MutatingReadbackPlanner::new(ReadbackMutation::Reverse)),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        let error = rejected(
            consumer.consume(&signed_event(&keypair)),
            "reordered action and dispatch bindings must fail closed",
        );
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );
    }

    #[test]
    fn production_consumer_rejects_partial_durable_response_bindings() {
        let keypair = Keypair::from_seed(&[87_u8; 32]);
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(OneFindingCorrelation),
            Arc::new(ReverseLexicographicAttestor),
            Arc::new(MutatingReadbackPlanner::new(ReadbackMutation::DropLast)),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        let error = rejected(
            consumer.consume(&signed_event(&keypair)),
            "missing one-to-one action and dispatch binding must fail closed",
        );
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );
    }

    struct FailSecondAttestation {
        calls: Mutex<u32>,
    }

    impl CorrelationAttestor for FailSecondAttestation {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn attest(
            &self,
            _: &CorrelationOutcome,
        ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
            let mut calls = self.calls.lock().map_err(|_| PortError::unavailable())?;
            *calls = calls.saturating_add(1);
            if *calls == 2 {
                Err(PortError::integrity_failure())
            } else {
                Ok(vec![authoritative_finding()])
            }
        }
    }

    #[test]
    fn attestation_failure_never_partially_publishes_raw_findings_to_planning() {
        let keypair = Keypair::from_seed(&[74_u8; 32]);
        let planner = Arc::new(RecordingPlanner::default());
        let attestor = Arc::new(FailSecondAttestation {
            calls: Mutex::new(0),
        });
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(TwoOutcomeCorrelation),
            Arc::clone(&attestor) as Arc<dyn CorrelationAttestor>,
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));
        assert!(consumer.consume(&signed_event(&keypair)).is_err());
        assert_eq!(attestor.calls.lock().map_or(0, |calls| *calls), 2);
        assert!(planner
            .batches
            .lock()
            .is_ok_and(|batches| batches.is_empty()));
    }

    struct RecoveryPolicy {
        artifacts_unavailable: bool,
    }

    impl AttestedFindingResponsePolicyPlanner for RecoveryPolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &chio_security_types::ports::AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            let mut selection = response_policy_selection();
            selection.ttl_ms = 100_000;
            selection.operator_capability.expires_at_unix_ms = 200_000;
            Ok(selection)
        }

        fn load_admission_artifacts(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &AdmissionArtifactRef,
        ) -> PortResult<AttestedFindingAdmissionArtifacts> {
            if self.artifacts_unavailable {
                Err(PortError::unavailable())
            } else {
                Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new([
                    74_u8; 32
                ])))
            }
        }
    }

    struct GovernedRecoveryPolicy {
        artifacts_unavailable: bool,
    }

    impl AttestedFindingResponsePolicyPlanner for GovernedRecoveryPolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &chio_security_types::ports::AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            let mut selection = response_policy_selection();
            selection.ttl_ms = 100_000;
            selection.operator_capability.expires_at_unix_ms = 200_000;
            selection.approval_requirement = ResponseApprovalRequirement::Governed {
                policy_id: record("governed-recovery-policy"),
            };
            Ok(selection)
        }

        fn load_admission_artifacts(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &AdmissionArtifactRef,
        ) -> PortResult<AttestedFindingAdmissionArtifacts> {
            if self.artifacts_unavailable {
                Err(PortError::unavailable())
            } else {
                Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new([
                    74_u8; 32
                ])))
            }
        }
    }

    struct RecoveryCoordinator {
        fail_prepare: bool,
        fail_execute: bool,
        never_committed: bool,
        allow_expired_termination: bool,
        live_ready: bool,
        committed_recovery: Option<(Digest32, AttestedFindingResponseCompletionProof)>,
        dispatch_committed_recovery:
            Option<(Digest32, AttestedFindingResponseCompletionProof)>,
        resume_integrity_failure: bool,
        recovery_calls: Option<Arc<AtomicUsize>>,
        resume_calls: Option<Arc<AtomicUsize>>,
        termination_calls: Arc<AtomicUsize>,
        cancel_calls: Arc<AtomicUsize>,
        effects: Arc<AtomicUsize>,
    }

    impl RecoveryCoordinator {
        fn new(fail_prepare: bool, fail_execute: bool, effects: Arc<AtomicUsize>) -> Self {
            Self {
                fail_prepare,
                fail_execute,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: true,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: None,
                termination_calls: Arc::new(AtomicUsize::new(0)),
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn never_committed(
            effects: Arc<AtomicUsize>,
            termination_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: false,
                fail_execute: false,
                never_committed: true,
                allow_expired_termination: false,
                live_ready: true,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: None,
                termination_calls,
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn expired_never_committed(
            effects: Arc<AtomicUsize>,
            termination_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: true,
                allow_expired_termination: true,
                live_ready: false,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: None,
                termination_calls,
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn committed(
            plan_hash: Digest32,
            proof: AttestedFindingResponseCompletionProof,
            recovery_calls: Arc<AtomicUsize>,
            effects: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: false,
                committed_recovery: Some((plan_hash, proof)),
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: Some(recovery_calls),
                resume_calls: None,
                termination_calls: Arc::new(AtomicUsize::new(0)),
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn dispatch_committed(
            plan_hash: Digest32,
            proof: AttestedFindingResponseCompletionProof,
            resume_calls: Arc<AtomicUsize>,
            effects: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: false,
                committed_recovery: None,
                dispatch_committed_recovery: Some((plan_hash, proof)),
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: Some(resume_calls),
                termination_calls: Arc::new(AtomicUsize::new(0)),
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn resume_integrity_failure(
            resume_calls: Arc<AtomicUsize>,
            termination_calls: Arc<AtomicUsize>,
            effects: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: false,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: true,
                recovery_calls: None,
                resume_calls: Some(resume_calls),
                termination_calls,
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn with_cancel_calls(mut self, cancel_calls: Arc<AtomicUsize>) -> Self {
            self.cancel_calls = cancel_calls;
            self
        }
    }

    impl AttestedFindingResponseCoordinator for RecoveryCoordinator {
        fn ensure_configured(&self) -> PortResult<()> {
            Ok(())
        }

        fn ensure_ready(&self) -> PortResult<()> {
            if self.live_ready {
                Ok(())
            } else {
                Err(PortError::unavailable())
            }
        }

        fn recover_committed(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            dispatch_id: &RecordId,
        ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
            let Some((expected_plan_hash, proof)) = self.committed_recovery.as_ref() else {
                return Ok(None);
            };
            if &response_plan.plan_hash != expected_plan_hash
                || proof.dispatch_id() != dispatch_id
            {
                return Err(PortError::integrity_failure());
            }
            if let Some(calls) = self.recovery_calls.as_ref() {
                calls.fetch_add(1, Ordering::AcqRel);
            }
            Ok(Some(proof.clone()))
        }

        fn resume_dispatch_committed(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingDispatchCommittedResume> {
            if let Some(calls) = self.resume_calls.as_ref() {
                calls.fetch_add(1, Ordering::AcqRel);
            }
            if self.resume_integrity_failure {
                return Err(PortError::integrity_failure());
            }
            let Some((expected_plan_hash, proof)) =
                self.dispatch_committed_recovery.as_ref()
            else {
                return Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted);
            };
            if &response_plan.plan_hash != expected_plan_hash
                || binding.validate_for_plan(response_plan).is_err()
                || proof.dispatch_id() != &binding.dispatch_id
            {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingDispatchCommittedResume::Completed(
                proof.clone(),
            ))
        }

        fn reconstruct_pre_dispatch(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            artifacts: AttestedFindingAdmissionArtifacts,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
            let prepared = self.prepare_admission(plan, artifacts)?;
            if prepared.durable_dispatch_binding(plan.response_plan())? != *binding {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingPreDispatchReconstruction::Prepared(Box::new(
                prepared,
            )))
        }

        fn terminate_never_committed(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            binding: &PreparedActiveResponseDispatchBinding,
            current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
        ) -> PortResult<()> {
            if !self.never_committed
                || binding.validate_for_plan(response_plan).is_err()
            {
                return Err(PortError::integrity_failure());
            }
            if current_artifacts.is_none() && !self.allow_expired_termination {
                return Err(PortError::integrity_failure());
            }
            self.termination_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn prepare_admission(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            _: AttestedFindingAdmissionArtifacts,
        ) -> PortResult<PreparedAttestedFindingResponse> {
            if plan.response_plan().policy_hash != Digest32::new([31_u8; 32])
                || plan.admission_artifact_digest() != Some(&Digest32::new([74_u8; 32]))
            {
                return Err(PortError::integrity_failure());
            }
            if self.fail_prepare {
                return Err(PortError::unavailable());
            }
            Ok(PreparedAttestedFindingResponse::synthetic(
                RecordId::new(format!(
                    "recovery-dispatch-{}",
                    plan.response_plan().action_id.as_str()
                ))
                .map_err(|_| PortError::integrity_failure())?,
            ))
        }

        fn cancel_prepared(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &PreparedAttestedFindingResponse,
        ) -> PortResult<()> {
            self.cancel_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn execute_prepared(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            prepared: PreparedAttestedFindingResponse,
        ) -> PortResult<AttestedFindingResponseCompletionProof> {
            if self.never_committed {
                return Err(PortError::new(
                    PortErrorKind::InvalidData,
                    ErrorCode::new("active_response.never_committed")
                        .map_err(|_| PortError::integrity_failure())?,
                ));
            }
            if self.fail_execute {
                return Err(PortError::unavailable());
            }
            self.effects.fetch_add(1, Ordering::AcqRel);
            Ok(AttestedFindingResponseCompletionProof::synthetic(
                prepared.dispatch_id().clone(),
                AttestedFindingResponseCompletionOutcome::Activated,
                OpaqueReceiptRef::new(format!(
                    "recovery-evidence-{}",
                    plan.response_plan().action_id.as_str()
                ))
                .map_err(|_| PortError::integrity_failure())?,
                Digest32::new([75_u8; 32]),
            ))
        }
    }

    fn publish_recovery_batch(
        store: &SqliteSecurityStateStore,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
    ) -> AttestedFindingBatchPublication {
        let publication = build_attested_finding_batch_publication(findings)
            .unwrap_or_else(|error| panic!("recovery publication: {error}"));
        store
            .publish_attested_finding_batch(&publication)
            .unwrap_or_else(|error| panic!("publish recovery batch: {error}"));
        publication
    }

    fn recovery_planner(
        store: Arc<SqliteSecurityStateStore>,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
        policy: Arc<dyn AttestedFindingResponsePolicyPlanner>,
        coordinator: Arc<dyn AttestedFindingResponseCoordinator>,
        clock: Arc<dyn SecurityClock>,
    ) -> DurableAttestedFindingBatchPlanner {
        DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
            store as Arc<dyn AttestedFindingResponseOutboxStore>,
            Arc::new(TestFindingAuthority::new(findings)),
            policy,
            coordinator,
            clock,
        )
        .unwrap_or_else(|error| panic!("recovery planner: {error}"))
    }

    struct RejectingGlobalScanOutboxStore {
        inner: Arc<SqliteSecurityStateStore>,
        global_scan_called: Arc<AtomicBool>,
    }

    #[derive(Clone, Copy)]
    enum AdmissionPreparedFailureMode {
        BeforeWrite,
        AfterWrite,
    }

    struct FailingAdmissionPreparedOutboxStore {
        inner: Arc<SqliteSecurityStateStore>,
        fail_next_admission_prepared: AtomicBool,
        mode: AdmissionPreparedFailureMode,
    }

    impl FailingAdmissionPreparedOutboxStore {
        fn new(
            inner: Arc<SqliteSecurityStateStore>,
            mode: AdmissionPreparedFailureMode,
        ) -> Self {
            Self {
                inner,
                fail_next_admission_prepared: AtomicBool::new(true),
                mode,
            }
        }
    }

    impl AttestedFindingResponseOutboxStore for FailingAdmissionPreparedOutboxStore {
        fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()> {
            self.inner
                .ensure_attested_finding_response_outbox_ready()
        }

        fn publish_attested_finding_response_plan(
            &self,
            publication: &AttestedFindingResponsePlanPublication,
        ) -> PortResult<CreateOutcome> {
            self.inner
                .publish_attested_finding_response_plan(publication)
        }

        fn load_attested_finding_response_outbox(
            &self,
            key: &AttestedFindingResponseOutboxKey,
        ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
            self.inner.load_attested_finding_response_outbox(key)
        }

        fn scan_unplanned_attested_finding_responses(
            &self,
            now_unix_ms: u64,
            limit: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.inner
                .scan_unplanned_attested_finding_responses(now_unix_ms, limit)
        }

        fn scan_incomplete_attested_finding_responses(
            &self,
            now_unix_ms: u64,
            limit: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.inner
                .scan_incomplete_attested_finding_responses(now_unix_ms, limit)
        }

        fn transition_attested_finding_response_outbox(
            &self,
            current: &AttestedFindingResponseOutboxRecord,
            transition: AttestedFindingResponseOutboxTransition,
        ) -> PortResult<AttestedFindingResponseOutboxRecord> {
            let inject_failure = matches!(
                &transition,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared { .. }
            ) && self
                .fail_next_admission_prepared
                .swap(false, Ordering::AcqRel);
            if inject_failure {
                match self.mode {
                    AdmissionPreparedFailureMode::BeforeWrite => {
                        return Err(PortError::unavailable());
                    }
                    AdmissionPreparedFailureMode::AfterWrite => {
                        self.inner.transition_attested_finding_response_outbox(
                            current,
                            transition,
                        )?;
                        return Err(PortError::unavailable());
                    }
                }
            }
            self.inner
                .transition_attested_finding_response_outbox(current, transition)
        }

        fn attested_finding_response_outbox_health(
            &self,
        ) -> PortResult<AttestedFindingResponseOutboxHealth> {
            self.inner.attested_finding_response_outbox_health()
        }
    }

    impl AttestedFindingResponseOutboxStore for RejectingGlobalScanOutboxStore {
        fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()> {
            self.inner
                .ensure_attested_finding_response_outbox_ready()
        }

        fn publish_attested_finding_response_plan(
            &self,
            publication: &AttestedFindingResponsePlanPublication,
        ) -> PortResult<CreateOutcome> {
            self.inner
                .publish_attested_finding_response_plan(publication)
        }

        fn load_attested_finding_response_outbox(
            &self,
            key: &AttestedFindingResponseOutboxKey,
        ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
            self.inner.load_attested_finding_response_outbox(key)
        }

        fn scan_unplanned_attested_finding_responses(
            &self,
            _: u64,
            _: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.global_scan_called.store(true, Ordering::Release);
            Err(PortError::unavailable())
        }

        fn scan_incomplete_attested_finding_responses(
            &self,
            _: u64,
            _: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.global_scan_called.store(true, Ordering::Release);
            Err(PortError::unavailable())
        }

        fn transition_attested_finding_response_outbox(
            &self,
            current: &AttestedFindingResponseOutboxRecord,
            transition: AttestedFindingResponseOutboxTransition,
        ) -> PortResult<AttestedFindingResponseOutboxRecord> {
            self.inner
                .transition_attested_finding_response_outbox(current, transition)
        }

        fn attested_finding_response_outbox_health(
            &self,
        ) -> PortResult<AttestedFindingResponseOutboxHealth> {
            self.inner.attested_finding_response_outbox_health()
        }
    }

    #[test]
    fn synchronous_batch_recovery_targets_its_batch_instead_of_the_global_backlog() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("exact-batch-recovery.sqlite"))
                .unwrap_or_else(|error| panic!("exact batch store: {error}")),
        );
        let older = authoritative_finding_with_identity(
            "finding-older-global-backlog",
            "rule-older-global-backlog",
            91,
        );
        let current = authoritative_finding_with_identity(
            "finding-current-exact-batch",
            "rule-current-exact-batch",
            92,
        );
        let older_publication =
            publish_recovery_batch(store.as_ref(), std::slice::from_ref(&older));
        let current_publication =
            build_attested_finding_batch_publication(std::slice::from_ref(&current))
                .unwrap_or_else(|error| panic!("current exact publication: {error}"));
        let global_scan_called = Arc::new(AtomicBool::new(false));
        let coordinator = Arc::new(RecordingResponseCoordinator::default());
        let findings = vec![older, current.clone()];
        let planner = DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
            Arc::new(RejectingGlobalScanOutboxStore {
                inner: Arc::clone(&store),
                global_scan_called: Arc::clone(&global_scan_called),
            }),
            Arc::new(TestFindingAuthority::new(&findings)),
            Arc::new(RecordingResponsePolicy),
            Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
            Arc::new(FixedClock(10_002)),
        )
        .unwrap_or_else(|error| panic!("exact batch planner: {error}"));

        planner
            .publish_attested_batch(std::slice::from_ref(&current))
            .unwrap_or_else(|error| panic!("exact batch publication: {error}"));

        assert!(!global_scan_called.load(Ordering::Acquire));
        let current_record = store
            .load_attested_finding_response_outbox(&recovery_outbox_key(
                &current_publication,
                0,
            ))
            .unwrap_or_else(|error| panic!("current exact response: {error}"))
            .unwrap_or_else(|| panic!("current exact response missing"));
        assert_eq!(
            current_record.completion_state,
            AttestedFindingResponseCompletionState::Completed
        );
        let older_record = store
            .load_attested_finding_response_outbox(&recovery_outbox_key(
                &older_publication,
                0,
            ))
            .unwrap_or_else(|error| panic!("older backlog response: {error}"))
            .unwrap_or_else(|| panic!("older backlog response missing"));
        assert_eq!(
            older_record.planning_state,
            AttestedFindingResponsePlanningState::Pending
        );
        assert_eq!(
            coordinator
                .executions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );
    }

    #[test]
    fn synchronous_batch_recovery_processes_every_binding_and_preserves_the_first_error() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("complete-batch-recovery.sqlite"))
                .unwrap_or_else(|error| panic!("complete batch store: {error}")),
        );
        let first = authoritative_finding_with_identity(
            "finding-first-terminal-failure",
            "rule-first-terminal-failure",
            93,
        );
        let second = authoritative_finding_with_identity(
            "finding-second-terminal-failure",
            "rule-second-terminal-failure",
            94,
        );
        let third = authoritative_finding_with_identity(
            "finding-third-success",
            "rule-third-success",
            95,
        );
        let findings = vec![first.clone(), second.clone(), third.clone()];
        let publication = build_attested_finding_batch_publication(&findings)
            .unwrap_or_else(|error| panic!("complete batch publication: {error}"));
        let first_error_code = ErrorCode::new("active_response.first_terminal_failure")
            .unwrap_or_else(|error| panic!("first error code: {error}"));
        let second_error_code = ErrorCode::new("active_response.second_terminal_failure")
            .unwrap_or_else(|error| panic!("second error code: {error}"));
        let policy = Arc::new(SelectiveArtifactResponsePolicy {
            rejected: BTreeMap::from([
                (first.evidence_id().clone(), first_error_code.clone()),
                (second.evidence_id().clone(), second_error_code.clone()),
            ]),
        });
        let coordinator = Arc::new(RecordingResponseCoordinator::default());
        let planner = recovery_planner(
            Arc::clone(&store),
            &findings,
            policy,
            Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
            Arc::new(FixedClock(10_002)),
        );

        let error = rejected(
            planner.publish_attested_batch(&findings),
            "the first terminal response error must fail the batch",
        );
        let replay_error = rejected(
            planner.publish_attested_batch(&findings),
            "terminal response replay must preserve the first batch error",
        );

        assert_eq!(error.code(), &first_error_code);
        assert_eq!(replay_error.code(), &first_error_code);
        for (ordinal, expected_error_code) in
            [(0_usize, &first_error_code), (1_usize, &second_error_code)]
        {
            let rejected = store
                .load_attested_finding_response_outbox(&recovery_outbox_key(
                    &publication,
                    ordinal,
                ))
                .unwrap_or_else(|load_error| panic!("rejected response: {load_error}"))
                .unwrap_or_else(|| panic!("rejected response missing"));
            assert_eq!(
                rejected.admission_state,
                AttestedFindingResponseAdmissionState::Rejected
            );
            assert_eq!(rejected.last_error_code.as_ref(), Some(expected_error_code));
        }
        let completed = store
            .load_attested_finding_response_outbox(&recovery_outbox_key(&publication, 2))
            .unwrap_or_else(|error| panic!("completed response: {error}"))
            .unwrap_or_else(|| panic!("completed response missing"));
        assert_eq!(
            completed.completion_state,
            AttestedFindingResponseCompletionState::Completed
        );
        assert_eq!(
            coordinator
                .executions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );
    }

    fn recovery_outbox_key(
        publication: &AttestedFindingBatchPublication,
        ordinal: usize,
    ) -> AttestedFindingResponseOutboxKey {
        let binding = &publication.body.bindings.as_slice()[ordinal];
        AttestedFindingResponseOutboxKey {
            tenant_id: binding.tenant_id.clone(),
            action_id: binding.action_id.clone(),
        }
    }

    fn prepared_binding_for_outbox(
        record: &AttestedFindingResponseOutboxRecord,
        dispatch_id: RecordId,
    ) -> PreparedActiveResponseDispatchBinding {
        let response_plan = &record
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("prepared binding publication missing"))
            .body
            .response_plan;
        PreparedAttestedFindingResponse::synthetic(dispatch_id)
            .durable_dispatch_binding(response_plan)
            .unwrap_or_else(|error| panic!("synthetic prepared binding: {error}"))
    }

    #[test]
    fn durable_recovery_crosses_plan_artifact_prepare_and_completion_crash_boundaries() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("response-crashes.sqlite"))
                .unwrap_or_else(|error| panic!("recovery store: {error}")),
        );
        let findings = vec![authoritative_finding()];
        let publication = publish_recovery_batch(store.as_ref(), &findings);
        let key = recovery_outbox_key(&publication, 0);
        let clock = Arc::new(MutableClock::new(10_002));
        let effects = Arc::new(AtomicUsize::new(0));

        let plan_only = recovery_planner(
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
        let report = plan_only
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("plan-only pass: {error}"));
        assert_eq!(report.plans_published, 1);
        let planned = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("planned row: {error}"))
            .unwrap_or_else(|| panic!("planned row missing"));
        assert_eq!(planned.planning_state, AttestedFindingResponsePlanningState::Planned);
        assert!(planned.admission_artifact_digest.is_none());

        let fail_prepare = recovery_planner(
            Arc::clone(&store),
            &findings,
            Arc::new(RecoveryPolicy {
                artifacts_unavailable: false,
            }),
            Arc::new(RecoveryCoordinator::new(
                true,
                false,
                Arc::clone(&effects),
            )),
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
        );
        assert!(fail_prepare.resume_incomplete_pass(1).is_err());
        let artifact_bound = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("artifact-bound row: {error}"))
            .unwrap_or_else(|| panic!("artifact-bound row missing"));
        assert_eq!(artifact_bound.admission_artifact_digest, Some(Digest32::new([74_u8; 32])));
        assert_eq!(artifact_bound.admission_state, AttestedFindingResponseAdmissionState::Pending);

        clock.set(artifact_bound.next_attempt_at_unix_ms.saturating_add(1));
        let fail_execute = recovery_planner(
            Arc::clone(&store),
            &findings,
            Arc::new(RecoveryPolicy {
                artifacts_unavailable: false,
            }),
            Arc::new(RecoveryCoordinator::new(
                false,
                true,
                Arc::clone(&effects),
            )),
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
        );
        assert!(fail_execute.resume_incomplete_pass(1).is_err());
        let prepared = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("prepared row: {error}"))
            .unwrap_or_else(|| panic!("prepared row missing"));
        assert_eq!(prepared.admission_state, AttestedFindingResponseAdmissionState::Prepared);
        assert_eq!(
            prepared.completion_state,
            AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
        );

        clock.set(prepared.next_attempt_at_unix_ms.saturating_add(1));
        let recovered = recovery_planner(
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
        recovered
            .resume_incomplete_pass(1)
            .unwrap_or_else(|error| panic!("completion recovery: {error}"));
        let completed = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("completed row: {error}"))
            .unwrap_or_else(|| panic!("completed row missing"));
        assert_eq!(completed.completion_state, AttestedFindingResponseCompletionState::Completed);
        assert_eq!(effects.load(Ordering::Acquire), 1);
    }
