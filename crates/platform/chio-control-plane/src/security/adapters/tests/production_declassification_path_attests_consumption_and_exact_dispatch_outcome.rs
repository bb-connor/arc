use super::*;


    #[test]
    fn production_declassification_path_attests_consumption_and_exact_dispatch_outcome() {
        let authority = Keypair::from_seed(&[75; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let declassification_store = Arc::new(
            open_declassification_test_store(directory.path().join("declassification.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            declassification_store as Arc<dyn DeclassificationEvidenceCommitStore>,
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
                RecordId::new("dispatch-receipt-test")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("declassification outcome recorder"));
        outcome
            .record(DeclassificationDispatchOutcome::Released)
            .unwrap_or_else(|error| panic!("record released outcome: {error}"));

        let bodies = receipts.bodies();
        assert_eq!(bodies.len(), 2);
        let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationConsumption(
            consumed,
        ) = &bodies[0]
        else {
            panic!("first declassification receipt must attest consumption");
        };
        let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationOutcome(
            released,
        ) = &bodies[1]
        else {
            panic!("second declassification receipt must attest outcome");
        };
        assert_eq!(consumed.grant_id, released.grant_id);
        assert_eq!(consumed.grant_hash, released.grant_hash);
        assert_eq!(consumed.request_hash, released.request_hash);
        assert_eq!(
            released.header.prior_receipt_ids.as_slice(),
            [bodies[0]
                .evidence_id()
                .unwrap_or_else(|error| panic!("consumption evidence id: {error}"))]
        );
        assert_eq!(released.to_state, DeclassificationUseState::Released);
    }
