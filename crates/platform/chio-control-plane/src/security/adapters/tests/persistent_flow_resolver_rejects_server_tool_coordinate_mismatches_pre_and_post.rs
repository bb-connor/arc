use super::*;

#[test]
fn persistent_flow_resolver_rejects_server_tool_coordinate_mismatches_pre_and_post() {
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = PersistentFlowResolver::new(
        server_tool_flow_registry(),
        Arc::new(FakeFlowStore::new(flow_snapshot(7))),
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
    let response = serde_json::json!({"status": "complete"});

    for (server_id, tool_name) in [
        ("server-a", "text_editor_20241022"),
        ("server-b", "bash_20241022"),
    ] {
        let mut request = server_tool_flow_request();
        request.server_id = server_id.to_string();
        request.tool_name = tool_name.to_string();
        assert!(matches!(
            FlowPreInvocationResolver::resolve(
                &resolver,
                &FlowPreInvocationInput {
                    security_context: &security_context,
                    request: &request,
                },
            ),
            Err(chio_flow::FlowDenial::InvalidManifest)
        ));
        assert!(matches!(
            FlowPostInvocationResolver::resolve(
                &resolver,
                &FlowPostInvocationInput {
                    security_context: &security_context,
                    request: &request,
                    response: &response,
                },
            ),
            Err(chio_flow::FlowDenial::InvalidManifest)
        ));
    }
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
}
