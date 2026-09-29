use super::*;


        #[test]
    fn committed_admission_without_dispatch_survives_cold_recovery() {
        use chio_kernel::active_response_test_support::{
            seed_committed_admission, CommittedAdmissionFixture,
        };
        use chio_kernel::approval::{ApprovalReservationMember, ApprovalSetReservationInput};
        use chio_security_types::ports::ResponseDispatchApproval;

        let fixture = real_adapter_fixture();
        let plan = fixture.plan.response_plan().clone();
        let approval_set = ApprovalSetReservationInput::new(
            "55".repeat(32),
            vec![
                ApprovalReservationMember::new("committed-token".to_owned(), "66".repeat(32))
                    .unwrap_or_else(|error| panic!("committed approval member: {error}")),
            ],
            plan.expires_at_unix_ms / 1_000,
        )
        .unwrap_or_else(|error| panic!("committed approval set: {error}"));
        let binding = seed_committed_admission(
            &fixture.runtime.kernel,
            CommittedAdmissionFixture {
                executor_authority: fixture.runtime.executor.identity(),
                governed_intent_hash: "77".repeat(32),
                policy_decision_hash: "88".repeat(32),
                // The committed authorization must precede the store's trusted
                // clock. The executor clock deliberately models later recovery.
                authorized_at_unix_ms: plan.created_at_unix_ms,
                response_plan: plan.clone(),
            },
            &approval_set,
        )
        .unwrap_or_else(|error| panic!("seed admission commitment: {error}"));
        let ResponseDispatchApproval::Governed {
            admission_operation_id,
            ..
        } = &binding.approval
        else {
            panic!("committed admission must be governed");
        };
        assert_eq!(
            fixture
                .runtime
                .admission_operations
                .count_unresolved(AdmissionOperationKind::GovernedActiveResponse,)
                .unwrap_or_else(|error| panic!("admission inventory: {error}")),
            1
        );
        assert_eq!(
            real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"),
            0
        );
        assert_eq!(fixture.runtime.effects.executions(), 0);
        drop(fixture.runtime);

        let mut total_effects = 0;
        for expected_new_effects in [1, 0] {
            let cold = build_real_adapter_runtime(
                &fixture.paths,
                &fixture.operator_authority,
                &fixture.executor_signer,
                &fixture.submission_authority,
                &fixture.threshold_policy_authority,
                &fixture.threshold_requirement,
                &fixture.finding,
                &plan,
                Arc::clone(&fixture.clock),
                false,
            );
            let resumed = cold
                .kernel
                .resume_dispatch_committed_active_response(&plan, &binding)
                .unwrap_or_else(|error| {
                    panic!("recover committed admission after restart: {error:?}")
                });
            let chio_kernel::DispatchCommittedActiveResponseResume::Completed(evidence) = resumed
            else {
                panic!("committed recovery lost its commitment");
            };
            assert_eq!(evidence.dispatch_id(), &binding.dispatch_id);
            assert_eq!(
                evidence.outcome(),
                chio_kernel::ActiveResponseExecutionOutcome::Activated
            );
            assert_eq!(cold.effects.executions(), expected_new_effects);
            total_effects += cold.effects.executions();
            let operation = cold
                .admission_operations
                .load(admission_operation_id.as_str())
                .unwrap_or_else(|error| panic!("committed terminal operation: {error}"))
                .unwrap_or_else(|| panic!("committed operation missing"));
            assert_eq!(operation.state(), AdmissionOperationState::Completed);
            assert_eq!(
                real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"),
                1
            );
        }
        assert_eq!(total_effects, 1);
    }
