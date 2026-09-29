use super::*;

#[test]
fn idle_watermark_finalizes_a_single_tail_event_without_a_later_event() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("idle-tail-correlation.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let keypair = Keypair::from_seed(&[98_u8; 32]);
    let event = signed_event_kind(
        "native-idle-tail",
        SecurityEventKind::CanaryInvocation,
        &keypair,
    );
    let clock = Arc::new(MutableClock::new(10_000));
    let event_verifier = Arc::new(
        NativeSecurityEventVerifier::new(
            Arc::clone(&clock) as Arc<dyn Clock>,
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant(),
                producer_id: producer(),
                producer_key_id: record("detector-key-v1"),
                policy_version: record("policy-v1"),
                producer_key: keypair.public_key(),
            }],
            Vec::new(),
            60_000,
            200,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}")),
    );
    let ingress =
        VerifiedSecurityEventIngress::new(Arc::clone(&event_verifier), Arc::clone(&store))
            .unwrap_or_else(|error| panic!("ingress: {error}"));
    ingress
        .verify_and_append(&event)
        .unwrap_or_else(|error| panic!("enqueue tail event: {error}"));

    let correlation = Arc::new(
        SqliteTemporalCorrelationPort::new(
            Arc::clone(&store),
            CorrelationPolicy::new(200, 4_096, 8, false)
                .unwrap_or_else(|error| panic!("correlation policy: {error}")),
            vec![native_tripwire_rule()],
        )
        .unwrap_or_else(|error| panic!("correlation port: {error}")),
    );
    let planner = durable_test_planner(&store);
    let consumer = Arc::new(
        ProductionCorrelationConsumer::from_parts(
            event_verifier,
            correlation,
            Arc::new(OneFindingAttestor),
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        )
        .unwrap_or_else(|error| panic!("consumer: {error}")),
    );
    let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
    let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
        .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));

    assert_eq!(
        drainer
            .drain_once(16)
            .unwrap_or_else(|error| panic!("defer tail event: {error}")),
        0
    );
    assert_eq!(
        store
            .count_pending_correlation_events()
            .unwrap_or_else(|error| panic!("pending deferred tail: {error}")),
        1
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect deferred tail: {error}"));
    let deferred_outcomes: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_correlation_outcomes",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count deferred outcomes: {error}"));
    assert_eq!(deferred_outcomes, 0);

    clock.set(10_100);
    assert_eq!(
        drainer
            .drain_once(16)
            .unwrap_or_else(|error| panic!("flush idle tail: {error}")),
        1
    );
    assert_eq!(
        store
            .count_pending_correlation_events()
            .unwrap_or_else(|error| panic!("pending after idle flush: {error}")),
        0
    );
    for table in [
        "security_correlation_outcomes",
        "security_attested_finding_batches",
        "security_attested_finding_response_outbox",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("count {table}: {error}"));
        assert_eq!(
            count, 1,
            "idle flush did not commit exactly one {table} row"
        );
    }
}
