use super::*;

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
    let ingress =
        VerifiedSecurityEventIngress::new(Arc::new(verifier(&keypair)), Arc::clone(&store))
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
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
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
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("recount {table}: {error}"));
        assert_eq!(count, 1, "attestation retry duplicated {table}");
    }
}
