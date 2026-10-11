use super::*;

#[test]
fn stale_authoritative_generation_denies_before_classification() {
    let store = Arc::new(FakeFlowStore::new(flow_snapshot(8)));
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = PersistentFlowResolver::new(
        flow_registry(),
        store,
        classifier.clone(),
        Arc::new(FixedClock(150_000)),
        flow_config(),
    );
    let key = flow_key();
    let security_context = SecurityInvocationContextV1::new(
        key.tenant_id,
        key.session_id,
        key.principal_id,
        key.isolation_epoch_id,
        key.lineage_id,
        7,
    )
    .with_flow_state_generation(7);
    let request = flow_request();
    let input = FlowPreInvocationInput {
        security_context: &security_context,
        request: &request,
    };
    assert_eq!(
        FlowPreInvocationResolver::resolve(&resolver, &input),
        Err(chio_flow::FlowDenial::StateChanged)
    );
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
}
