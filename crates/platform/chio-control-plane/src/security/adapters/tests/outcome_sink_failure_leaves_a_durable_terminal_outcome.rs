use super::*;


    #[test]
    fn outcome_sink_failure_leaves_a_durable_terminal_outcome() {
        let authority = Keypair::from_seed(&[78; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            open_declassification_test_store(directory.path().join("outcome-sink-failure.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(ToggleSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
            receipts.clone() as Arc<dyn ExactSecurityReceiptSink>,
        );
        let clock = Arc::new(AdvancingClock::new(150_000));
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            clock.clone(),
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
        let mut recorder = resolver
            .commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("outcome-sink-failure-dispatch")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("outcome recorder missing"));
        receipts.rejecting.store(true, Ordering::Release);

        assert!(matches!(
            recorder.record(DeclassificationDispatchOutcome::Released),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        ));
        let use_record = store
            .load_declassification_use(&DeclassificationUseQuery {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            })
            .unwrap_or_else(|error| panic!("load terminal use: {error:?}"))
            .unwrap_or_else(|| panic!("terminal use missing"));
        assert_eq!(use_record.state, DeclassificationUseState::Released);
        assert_eq!(use_record.consumed_at_unix_ms, 150_001);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 5);
    }
