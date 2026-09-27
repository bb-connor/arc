    #[test]
    fn legacy_admission_without_dispatch_survives_receipt_migration_and_cold_recovery() {
        use chio_kernel::active_response_test_support::{
            seed_historical_admission, HistoricalAdmissionFixture,
        };
        use chio_kernel::approval::{ApprovalReservationMember, ApprovalSetReservationInput};
        use chio_security_types::ports::ResponseDispatchApproval;

        let fixture = real_adapter_fixture();
        let mut plan = fixture.plan.response_plan().clone();
        plan.execution = chio_security_types::PlanProvenance::Legacy;
        let body = serde_json::to_value(plan.authorization_body())
            .unwrap_or_else(|error| panic!("historical body: {error}"));
        let hash = GovernedResponsePlanIntentBody::compute_plan_body_digest(&body)
            .unwrap_or_else(|error| panic!("historical hash: {error}"));
        plan.plan_hash = Digest32::new(*hash.as_bytes());
        assert!(matches!(chio_security_types::FreshLiveAdmission::new(plan.clone()),
            Err(chio_security_types::DispatchRejection::LegacyPlanFreshDispatch)));
        let approval_set = ApprovalSetReservationInput::new(
            "55".repeat(32),
            vec![ApprovalReservationMember::new("historical-token".to_owned(), "66".repeat(32))
                .unwrap_or_else(|error| panic!("historical approval member: {error}"))],
            plan.expires_at_unix_ms / 1_000,
        ).unwrap_or_else(|error| panic!("historical approval set: {error}"));
        let binding = seed_historical_admission(
            &fixture.runtime.kernel,
            HistoricalAdmissionFixture {
                executor_authority: fixture.runtime.executor.identity(),
                governed_intent_hash: "77".repeat(32),
                policy_decision_hash: "88".repeat(32),
                // The historical authorization must precede the store's trusted
                // clock. The executor clock deliberately models later recovery.
                authorized_at_unix_ms: plan.created_at_unix_ms,
                response_plan: plan.clone(),
            },
            &approval_set,
        ).unwrap_or_else(|error| panic!("seed pre-upgrade admission commitment: {error}"));
        let ResponseDispatchApproval::Governed { admission_operation_id, .. } = &binding.approval else {
            panic!("historical admission must be governed");
        };
        assert_eq!(fixture.runtime.admission_operations.count_unresolved(
            AdmissionOperationKind::GovernedActiveResponse,
        ).unwrap_or_else(|error| panic!("admission inventory: {error}")), 1);
        assert_eq!(real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"), 0);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        drop(fixture.runtime);

        // Recreate the previous receipt schema exactly at the changed boundary.
        // No dispatch/effect exists yet. The admission and approval commitments
        // remain in their original stores across the receipt forward migration.
        let connection = Connection::open(&fixture.paths.receipts)
            .unwrap_or_else(|error| panic!("open historical receipt schema: {error}"));
        connection.execute_batch(
            "ALTER TABLE chio_tool_receipts DROP COLUMN attempted_cost_be;
             UPDATE chio_store_schema_versions SET version = 5 WHERE store_key = 'receipt';"
        ).unwrap_or_else(|error| panic!("restore receipt v5 fixture: {error}"));
        drop(connection);
        let migrated = SqliteReceiptStore::open(&fixture.paths.receipts)
            .unwrap_or_else(|error| panic!("forward-migrate historical receipts: {error}"));
        drop(migrated);
        let connection = Connection::open(&fixture.paths.receipts)
            .unwrap_or_else(|error| panic!("inspect migrated receipt schema: {error}"));
        let version: u32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'", [], |row| row.get(0),
        ).unwrap_or_else(|error| panic!("receipt migration version: {error}"));
        assert_eq!(version, 6);
        drop(connection);

        let mut total_effects = 0;
        for expected_new_effects in [1, 0] {
            let cold = build_real_adapter_runtime(
                &fixture.paths, &fixture.operator_authority, &fixture.executor_signer,
                &fixture.submission_authority, &fixture.threshold_policy_authority,
                &fixture.threshold_requirement, &fixture.finding, &plan,
                Arc::clone(&fixture.clock), false,
            );
            let resumed = cold.kernel.resume_dispatch_committed_active_response(&plan, &binding)
                .unwrap_or_else(|error| panic!("recover historical admission after migration: {error:?}"));
            let chio_kernel::DispatchCommittedActiveResponseResume::Completed(evidence) = resumed else {
                panic!("historical recovery lost its commitment");
            };
            assert_eq!(evidence.dispatch_id(), &binding.dispatch_id);
            assert_eq!(evidence.outcome(), chio_kernel::ActiveResponseExecutionOutcome::Activated);
            assert_eq!(cold.effects.executions(), expected_new_effects);
            total_effects += cold.effects.executions();
            let operation = cold.admission_operations.load(admission_operation_id.as_str())
                .unwrap_or_else(|error| panic!("historical terminal operation: {error}"))
                .unwrap_or_else(|| panic!("historical operation missing"));
            assert_eq!(operation.state(), AdmissionOperationState::Completed);
            assert_eq!(real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"), 1);
        }
        assert_eq!(total_effects, 1);
    }
