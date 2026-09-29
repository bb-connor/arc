use super::*;

#[test]
fn future_fifo_prefix_does_not_starve_a_later_due_event() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("future-prefix-correlation.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let keypair = Keypair::from_seed(&[100_u8; 32]);
    let future = signed_event_kind_at(
        "native-future-prefix",
        SecurityEventKind::CanaryInvocation,
        100_000,
        100_000,
        &keypair,
    );
    let due = signed_event_kind_at(
        "native-due-behind-prefix",
        SecurityEventKind::CanaryInvocation,
        40_000,
        100_000,
        &keypair,
    );
    let clock = Arc::new(MutableClock::new(100_000));
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
            120_000,
            50_000,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}")),
    );
    let ingress =
        VerifiedSecurityEventIngress::new(Arc::clone(&event_verifier), Arc::clone(&store))
            .unwrap_or_else(|error| panic!("ingress: {error}"));
    ingress
        .verify_and_append(&future)
        .unwrap_or_else(|error| panic!("enqueue future prefix: {error}"));
    ingress
        .verify_and_append(&due)
        .unwrap_or_else(|error| panic!("enqueue due event: {error}"));

    let correlation = Arc::new(
        SqliteTemporalCorrelationPort::new(
            Arc::clone(&store),
            CorrelationPolicy::new(50_000, 4_096, 8, false)
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
            .drain_once(1)
            .unwrap_or_else(|error| panic!("drain due event: {error}")),
        1
    );
    let pending = store
        .load_pending_correlation_events(1)
        .unwrap_or_else(|error| panic!("load remaining future event: {error}"));
    assert_eq!(pending.as_slice(), std::slice::from_ref(&future));
}
