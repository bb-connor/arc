use super::*;


    #[test]
    fn pre_dispatch_port_rejects_bytes_from_another_request_before_classification() {
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
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
        let request = flow_request();
        let other_request = {
            let mut value = request.clone();
            value.arguments = serde_json::json!({"safe": false});
            value
        };
        let other_bytes = chio_core::canonical_json_bytes(&other_request)
            .unwrap_or_else(|error| panic!("canonical other request: {error}"));
        let dispatch_commitment_id = RecordId::new("dispatch-a")
            .unwrap_or_else(|error| panic!("dispatch commitment: {error}"));

        assert!(matches!(
            FlowPreDispatchPort::commit(
                &resolver,
                &FlowPreDispatchInput {
                    security_context: &security_context,
                    request: &request,
                    canonical_request: &other_bytes,
                    dispatch_commitment_id: &dispatch_commitment_id,
                },
            ),
            Err(chio_flow::FlowDenial::DeclassificationBindingMismatch)
        ));
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    }
