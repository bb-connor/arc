use super::*;


    #[test]
    fn production_flow_denial_path_emits_closed_native_receipt_from_resolved_runtime_facts() {
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let state = Arc::new(FakeFlowStore::new(flow_snapshot(7)));
        let config = FlowResolverConfig::new(
            restricted_label(),
            CategoryLabelMap::new(
                ClassifierId::new("classifier.empty")
                    .unwrap_or_else(|error| panic!("classifier: {error}")),
                ClassifierVersion::new("1")
                    .unwrap_or_else(|error| panic!("classifier version: {error}")),
                BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("category map: {error}")),
            BTreeMap::new(),
            10_000,
        )
        .unwrap_or_else(|error| panic!("flow config: {error}"))
        .with_receipt_evidence(
            receipts.clone() as Arc<dyn SecurityReceiptSink>,
            receipt_policy(),
        );
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            state.clone(),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();

        assert_eq!(
            FlowPreInvocationPort::evaluate(
                &resolver,
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
            ),
            Err(chio_flow::FlowDenial::PolicyFlowViolation)
        );
        let bodies = receipts.bodies();
        assert_eq!(bodies.len(), 1);
        let chio_core::receipt::security::ActiveDefenseReceiptBody::FlowDenial(body) = &bodies[0]
        else {
            panic!("flow denial must emit a flow-denial body");
        };
        assert_eq!(body.header.tenant_id.as_str(), "tenant-a");
        assert_eq!(body.request_hash.as_bytes().len(), 32);
        assert_eq!(body.denial_code.as_str(), "flow.policy_flow_violation");
        let retained = state
            .load(&flow_key())
            .unwrap_or_else(|error| panic!("taint: {error}"))
            .unwrap_or_else(|| panic!("missing taint"));
        assert_eq!(retained.principal_label, restricted_label());
        assert_eq!(retained.session_label, restricted_label());
        assert_eq!(retained.lineage_label, restricted_label());
    }
