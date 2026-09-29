use super::*;

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
