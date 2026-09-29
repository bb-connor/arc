use super::*;

#[test]
fn production_flow_denial_path_surfaces_receipt_persistence_failure() {
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
    .with_receipt_evidence(Arc::new(RejectingSecurityReceipts), receipt_policy());
    let resolver = PersistentFlowResolver::new(
        flow_registry(),
        Arc::new(FakeFlowStore::new(flow_snapshot(7))),
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
        Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
    );
}
