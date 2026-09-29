use crate::security::event_consumer::tests::*;
use super::*;


    #[test]
    fn committed_correlation_outcome_survives_crash_before_attestation_and_reaches_outbox_once() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("correlation-outcome-crash.sqlite");
        let keypair = Keypair::from_seed(&[95_u8; 32]);
        let event = signed_event_kind(
            "native-correlation-outcome-crash",
            SecurityEventKind::CanaryInvocation,
            &keypair,
        );
        let rule = native_tripwire_rule();

        {
            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("open ingress store: {error}")),
            );
            let event_verifier = Arc::new(verifier(&keypair));
            let ingress =
                VerifiedSecurityEventIngress::new(Arc::clone(&event_verifier), Arc::clone(&store))
                    .unwrap_or_else(|error| panic!("ingress: {error}"));
            ingress
                .verify_and_append(&event)
                .unwrap_or_else(|error| panic!("enqueue native event: {error}"));
            let verified = SecurityEventVerifierPort::verify(event_verifier.as_ref(), &event)
                .unwrap_or_else(|error| panic!("verify correlation event: {error}"));
            let correlation = SqliteTemporalCorrelationPort::new(
                Arc::clone(&store),
                native_correlation_policy(),
                vec![rule.clone()],
            )
            .unwrap_or_else(|error| panic!("correlation port: {error}"));
            let outcomes = correlation
                .correlate(&verified, 10_000)
                .unwrap_or_else(|error| panic!("commit correlation outcome: {error}"));
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome.status, CorrelationStatus::Matched);
            assert_eq!(outcomes[0].outcome.findings.len(), 1);
            assert_eq!(
                store
                    .count_pending_correlation_events()
                    .unwrap_or_else(|error| panic!("pending before crash: {error}")),
                1
            );
        }

        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("reopen after correlation crash: {error}")),
        );
        let correlation = Arc::new(
            SqliteTemporalCorrelationPort::new(
                Arc::clone(&store),
                native_correlation_policy(),
                vec![rule],
            )
            .unwrap_or_else(|error| panic!("recovered correlation port: {error}")),
        );
        let planner = durable_test_planner(&store);
        let consumer = Arc::new(
            ProductionCorrelationConsumer::from_parts(
                Arc::new(verifier(&keypair)),
                correlation,
                Arc::new(OneFindingAttestor),
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            )
            .unwrap_or_else(|error| panic!("recovered consumer: {error}")),
        );
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));
        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("recover committed outcome: {error}")),
            1
        );

        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect recovered pipeline: {error}"));
        for (table, expected) in [
            ("security_correlation_outcomes", 1_i64),
            ("security_attested_finding_batches", 1_i64),
            ("security_attested_finding_response_outbox", 1_i64),
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(count, expected, "unexpected durable row count for {table}");
        }
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after recovery: {error}")),
            0
        );
        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("replay committed outcome: {error}")),
            0
        );
    }
