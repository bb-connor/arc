use super::*;


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
