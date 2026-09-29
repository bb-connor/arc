use super::*;


    #[test]
    fn native_tripwire_ingress_recovers_and_persists_response_work_for_every_event_class() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let keypair = Keypair::from_seed(&[93_u8; 32]);
        for (event_id, event_kind) in [
            ("native-canary-ingress", SecurityEventKind::CanaryInvocation),
            (
                "native-honey-ingress",
                SecurityEventKind::TripwireObservation,
            ),
            (
                "native-watermark-ingress",
                SecurityEventKind::WatermarkObservation,
            ),
        ] {
            let path = directory.path().join(format!("{event_id}.sqlite"));
            let event = signed_event_kind(event_id, event_kind, &keypair);
            {
                let store = Arc::new(
                    SqliteSecurityStateStore::open(&path)
                        .unwrap_or_else(|error| panic!("open ingress store: {error}")),
                );
                let ingress = VerifiedSecurityEventIngress::new(
                    Arc::new(verifier(&keypair)),
                    Arc::clone(&store),
                )
                .unwrap_or_else(|error| panic!("ingress: {error}"));
                assert_eq!(
                    ingress
                        .verify_and_append(&event)
                        .unwrap_or_else(|error| panic!("enqueue native event: {error}")),
                    EventAppend::Inserted
                );
                assert_eq!(
                    store
                        .count_pending_correlation_events()
                        .unwrap_or_else(|error| panic!("pending ingress: {error}")),
                    1
                );
            }

            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("reopen after ingress crash: {error}")),
            );
            let finding = authoritative_finding();
            let planner = Arc::new(
                DurableAttestedFindingBatchPlanner::new(
                    Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
                    Arc::clone(&store) as Arc<dyn AttestedFindingResponseOutboxStore>,
                    Arc::new(TestFindingAuthority::new(std::slice::from_ref(&finding))),
                    Arc::new(RecordingResponsePolicy),
                    Arc::new(RecordingResponseCoordinator::default()),
                    Arc::new(FixedClock(10_002)),
                )
                .unwrap_or_else(|error| panic!("durable planner: {error}")),
            );
            let consumer = correlation_consumer(
                &keypair,
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            );
            let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
            let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
                .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));
            assert_eq!(
                drainer
                    .drain_once(16)
                    .unwrap_or_else(|error| panic!("recover native event: {error}")),
                1
            );
            assert_eq!(
                store
                    .count_pending_correlation_events()
                    .unwrap_or_else(|error| panic!("pending after recovery: {error}")),
                0
            );

            let connection = Connection::open(&path)
                .unwrap_or_else(|error| panic!("inspect native ingress state: {error}"));
            let finding_batches: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM security_attested_finding_batches",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("count finding batches: {error}"));
            let response_work: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM security_attested_finding_response_outbox",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("count response work: {error}"));
            assert_eq!(finding_batches, 1);
            assert_eq!(response_work, 1);

            let replay_ingress =
                VerifiedSecurityEventIngress::new(Arc::new(verifier(&keypair)), Arc::clone(&store))
                    .unwrap_or_else(|error| panic!("replay ingress: {error}"));
            assert_eq!(
                replay_ingress
                    .verify_and_append(&event)
                    .unwrap_or_else(|error| panic!("replay native event: {error}")),
                EventAppend::Duplicate
            );
            assert_eq!(
                store
                    .count_pending_correlation_events()
                    .unwrap_or_else(|error| panic!("pending after replay: {error}")),
                0
            );
        }
    }
