use super::*;

#[test]
fn pre_dispatch_port_commits_the_authoritative_fence_for_exact_kernel_bytes() {
    let store = Arc::new(FakeFlowStore::new(flow_snapshot(7)));
    let resolver = PersistentFlowResolver::new(
        flow_registry(),
        store.clone(),
        Arc::new(CountingEmptyClassifier::new()),
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
    let canonical_request = chio_core::canonical_json_bytes(&request)
        .unwrap_or_else(|error| panic!("canonical request: {error}"));
    let dispatch_commitment_id =
        RecordId::new("dispatch-a").unwrap_or_else(|error| panic!("dispatch commitment: {error}"));

    FlowPreDispatchPort::commit(
        &resolver,
        &FlowPreDispatchInput {
            security_context: &security_context,
            request: &request,
            canonical_request: &canonical_request,
            dispatch_commitment_id: &dispatch_commitment_id,
        },
    )
    .unwrap_or_else(|error| panic!("pre-dispatch commit: {error}"));

    assert_eq!(store.acquired.load(Ordering::SeqCst), 1);
    assert_eq!(store.committed.load(Ordering::SeqCst), 1);
}
