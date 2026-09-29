use super::*;


    #[test]
    fn persistent_flow_resolver_accepts_exact_server_tool_in_pre_and_post_stages() {
        let registry = server_tool_flow_registry();
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            registry.clone(),
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
        let request = server_tool_flow_request();
        let pre = FlowPreInvocationResolver::resolve(
            &resolver,
            &FlowPreInvocationInput {
                security_context: &security_context,
                request: &request,
            },
        )
        .unwrap_or_else(|error| panic!("resolve server-tool pre flow: {error}"));
        assert!(pre.runtime_egress);
        assert_eq!(
            pre.policy_clearances.as_slice(),
            &[InformationLabel::bottom()]
        );
        assert!(!pre.manifest.egress);

        let response = serde_json::json!({"status": "complete"});
        let post = FlowPostInvocationResolver::resolve(
            &resolver,
            &FlowPostInvocationInput {
                security_context: &security_context,
                request: &request,
                response: &response,
            },
        )
        .unwrap_or_else(|error| panic!("resolve server-tool post flow: {error}"));
        assert_eq!(post.operator_output_floor, restricted_label());
        assert!(!post.manifest.egress);
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 2);

        let exact_sidecar = registry
            .bridge_security_for_server_tool("server-a", "bash_20241022")
            .unwrap_or_else(|| panic!("server-tool sidecar must be admitted"));
        assert_eq!(exact_sidecar.server_id(), Some("server-a"));
        assert_eq!(exact_sidecar.tool_name(), Some("bash"));
        assert!(exact_sidecar.effective_egress());
        registry
            .validate_bridge_security("server-a", "bash_20241022", &exact_sidecar)
            .unwrap_or_else(|error| panic!("exact server-tool sidecar must validate: {error}"));

        let mut forged_value = serde_json::to_value(exact_sidecar)
            .unwrap_or_else(|error| panic!("serialize server-tool sidecar: {error}"));
        forged_value["manifest_digest"] = serde_json::json!("forged-manifest-digest");
        let forged = serde_json::from_value(forged_value)
            .unwrap_or_else(|error| panic!("deserialize forged server-tool sidecar: {error}"));
        assert!(registry
            .validate_bridge_security("server-a", "bash_20241022", &forged)
            .is_err());
    }
