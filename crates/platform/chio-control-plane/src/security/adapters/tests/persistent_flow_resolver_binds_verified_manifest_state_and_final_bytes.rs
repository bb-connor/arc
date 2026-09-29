use super::*;

#[test]
fn persistent_flow_resolver_binds_verified_manifest_state_and_final_bytes() {
    let store = Arc::new(FakeFlowStore::new(flow_snapshot(7)));
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = PersistentFlowResolver::new(
        flow_registry(),
        store.clone(),
        classifier.clone(),
        Arc::new(FixedClock(150_000)),
        flow_config(),
    );
    let key = flow_key();
    let security_context = SecurityInvocationContextV1::new(
        key.tenant_id.clone(),
        key.session_id.clone(),
        key.principal_id.clone(),
        key.isolation_epoch_id.clone(),
        key.lineage_id.clone(),
        7,
    )
    .with_flow_state_generation(7);
    let request = flow_request();
    let pre = FlowPreInvocationInput {
        security_context: &security_context,
        request: &request,
    };
    let admission = evaluate_pre_invocation(
        FlowPreInvocationResolver::resolve(&resolver, &pre)
            .unwrap_or_else(|error| panic!("resolve pre: {error}")),
    )
    .unwrap_or_else(|error| panic!("evaluate pre: {error}"));
    FlowPreInvocationResolver::persist(&resolver, &admission)
        .unwrap_or_else(|error| panic!("persist pre: {error}"));
    resolver
        .commit_dispatch(
            &pre,
            RecordId::new("dispatch-a").unwrap_or_else(|error| panic!("dispatch: {error}")),
        )
        .unwrap_or_else(|error| panic!("commit dispatch: {error}"));

    let response = serde_json::json!({"delivered": true});
    let post = FlowPostInvocationInput {
        security_context: &security_context,
        request: &request,
        response: &response,
    };
    let transition = evaluate_post_invocation(
        FlowPostInvocationResolver::resolve(&resolver, &post)
            .unwrap_or_else(|error| panic!("resolve post: {error}")),
    )
    .unwrap_or_else(|error| panic!("evaluate post: {error}"));
    FlowPostInvocationResolver::persist(&resolver, &transition)
        .unwrap_or_else(|error| panic!("persist post: {error}"));

    assert_eq!(classifier.calls.load(Ordering::SeqCst), 3);
    assert_eq!(store.acquired.load(Ordering::SeqCst), 1);
    assert_eq!(store.committed.load(Ordering::SeqCst), 1);
}
