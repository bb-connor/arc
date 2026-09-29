use super::*;


    #[test]
    fn flow_transition_identity_binds_the_canonical_payload() {
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
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
        let first = flow_request();
        let mut second = flow_request();
        second.arguments = serde_json::json!({"safe": false});
        let first_input = FlowPreInvocationInput {
            security_context: &security_context,
            request: &first,
        };
        let second_input = FlowPreInvocationInput {
            security_context: &security_context,
            request: &second,
        };
        let first_admission = evaluate_pre_invocation(
            FlowPreInvocationResolver::resolve(&resolver, &first_input)
                .unwrap_or_else(|error| panic!("first resolve: {error}")),
        )
        .unwrap_or_else(|error| panic!("first admission: {error}"));
        let second_admission = evaluate_pre_invocation(
            FlowPreInvocationResolver::resolve(&resolver, &second_input)
                .unwrap_or_else(|error| panic!("second resolve: {error}")),
        )
        .unwrap_or_else(|error| panic!("second admission: {error}"));

        assert_ne!(
            first_admission.taint_transition.transition_id,
            second_admission.taint_transition.transition_id
        );
    }
