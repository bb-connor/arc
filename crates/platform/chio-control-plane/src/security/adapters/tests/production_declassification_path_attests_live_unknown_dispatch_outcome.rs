use super::*;

#[test]
fn production_declassification_path_attests_live_unknown_dispatch_outcome() {
    let authority = Keypair::from_seed(&[80; 32]);
    let purpose =
        DeclassificationPurpose::new("support").unwrap_or_else(|error| panic!("purpose: {error}"));
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        open_declassification_test_store(directory.path().join("unknown-dispatch.sqlite"))
            .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
    );
    let receipts = Arc::new(RecordingSecurityReceipts::default());
    let config = declassifying_evidence_flow_config(
        &authority,
        store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        receipts.clone() as Arc<dyn ExactSecurityReceiptSink>,
    );
    let resolver = PersistentFlowResolver::new(
        declassification_registry(&purpose),
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
    let request = declassifying_flow_request(&authority, &purpose);
    let mut outcome = resolver
        .commit_dispatch(
            &FlowPreInvocationInput {
                security_context: &context,
                request: &request,
            },
            RecordId::new("unknown-dispatch-receipt-test")
                .unwrap_or_else(|error| panic!("dispatch: {error}")),
        )
        .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
        .unwrap_or_else(|| panic!("declassification outcome recorder"));
    outcome
        .record(DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch)
        .unwrap_or_else(|error| panic!("record unknown dispatch outcome: {error}"));

    let bodies = receipts.bodies();
    assert_eq!(bodies.len(), 2);
    bodies[1]
        .validate()
        .unwrap_or_else(|error| panic!("validate unknown-outcome receipt: {error:?}"));
    let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationOutcome(unknown) =
        &bodies[1]
    else {
        panic!("second declassification receipt must attest unknown outcome");
    };
    assert_eq!(unknown.to_state, DeclassificationUseState::OutcomeUnknown);
    assert_eq!(
        unknown.header.prior_receipt_ids.as_slice(),
        [bodies[0]
            .evidence_id()
            .unwrap_or_else(|error| panic!("consumption evidence id: {error}"))]
    );

    let use_record = store
        .load_declassification_use(&DeclassificationUseQuery {
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
        })
        .unwrap_or_else(|error| panic!("load unknown use: {error:?}"))
        .unwrap_or_else(|| panic!("unknown use missing"));
    assert_eq!(use_record.state, DeclassificationUseState::OutcomeUnknown);
    let evidence = store
        .load_declassification_evidence(&DeclassificationEvidenceQuery {
            tenant_id: use_record.tenant_id,
            grant_id: use_record.grant_id,
            phase: DeclassificationEvidencePhase::Outcome,
        })
        .unwrap_or_else(|error| panic!("load unknown outcome evidence: {error:?}"))
        .unwrap_or_else(|| panic!("unknown outcome evidence missing"));
    assert!(matches!(
        evidence.transition_binding,
        DeclassificationTransitionBinding::OutcomeUnknownAfterDispatch { .. }
    ));
}
