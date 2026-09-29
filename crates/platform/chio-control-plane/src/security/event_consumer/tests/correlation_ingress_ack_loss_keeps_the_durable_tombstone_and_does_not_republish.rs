use super::*;

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
