use super::*;


    #[test]
    fn real_kernel_approval_adapter_prepares_reconstructs_commits_and_cold_resumes_once() {
        let fixture = real_adapter_fixture();
        let prepared = fixture
            .runtime
            .coordinator
            .prepare_admission(&fixture.plan, fixture.artifacts.clone())
            .unwrap_or_else(|error| panic!("real adapter prepare: {error}"));
        let operation_id = real_adapter_prepared_operation_id(&prepared);
        let binding = prepared
            .durable_dispatch_binding(fixture.plan.response_plan())
            .unwrap_or_else(|error| panic!("real adapter durable binding: {error}"));
        let PreparedAttestedFindingResponse::Kernel(kernel_prepared) = &prepared else {
            panic!("real adapter preparation must retain the native request");
        };
        let portable_reservation = kernel_prepared.test_governed_approval()
            .as_ref()
            .unwrap_or_else(|| panic!("real adapter portable reservation missing"));
        assert_eq!(
            kernel_prepared.test_request().response_plan(),
            fixture.native_request().response_plan()
        );
        assert_eq!(
            governed_approval_request_from_native(&kernel_prepared.test_request())
                .unwrap_or_else(|error| panic!("project retained real adapter request: {error}")),
            fixture.governed_request()
        );
        assert_eq!(portable_reservation.request, fixture.governed_request());
        assert_eq!(portable_reservation.prepared_dispatch_binding, binding);
        assert_eq!(
            portable_reservation.expires_at_unix_ms,
            fixture.governed_request().proposal_expires_at_unix_ms
        );
        let reserved_operation = fixture
            .runtime
            .admission_operations
            .load(&operation_id)
            .unwrap_or_else(|error| panic!("load reserved real adapter operation: {error}"))
            .unwrap_or_else(|| panic!("reserved real adapter operation missing"));
        assert_eq!(
            reserved_operation.state(),
            AdmissionOperationState::ApprovalReserved
        );
        let reserved_approval = fixture
            .runtime
            .approvals
            .get_approval_reservation(&operation_id)
            .unwrap_or_else(|error| panic!("load reserved real adapter approval: {error}"))
            .unwrap_or_else(|| panic!("reserved real adapter approval missing"));
        assert_eq!(reserved_approval.state(), ReplayReservationState::Reserved);
        assert_eq!(
            real_adapter_mutation_snapshot(&fixture.paths),
            [1, 1, 1, 0, 0]
        );
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 0);

        let recreated = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
            fixture.runtime.executor.identity(),
            Arc::clone(&fixture.clock) as Arc<dyn Clock>,
            super::super::super::super::ActiveResponseExecutionProfile::Live,
        ));
        recreated
            .bind_kernel(Arc::clone(&fixture.runtime.kernel))
            .unwrap_or_else(|error| panic!("bind recreated real adapter: {error}"));
        let reconstructed = match recreated
            .reconstruct_pre_dispatch(&fixture.plan, fixture.artifacts.clone(), &binding)
            .unwrap_or_else(|error| panic!("reconstruct real adapter preparation: {error}"))
        {
            AttestedFindingPreDispatchReconstruction::Prepared(prepared) => *prepared,
            AttestedFindingPreDispatchReconstruction::NotPrepared => {
                panic!("real adapter reservation disappeared during reconstruction")
            }
        };
        assert_eq!(
            reconstructed
                .durable_dispatch_binding(fixture.plan.response_plan())
                .unwrap_or_else(|error| panic!("reconstructed real adapter binding: {error}")),
            binding
        );
        assert_eq!(
            real_adapter_prepared_operation_id(&reconstructed),
            operation_id
        );
        assert_eq!(
            fixture
                .runtime
                .admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| {
                    panic!("load reconstructed real adapter operation: {error}")
                })
                .unwrap_or_else(|| panic!("reconstructed real adapter operation missing"))
                .state(),
            AdmissionOperationState::ApprovalReserved
        );
        assert_eq!(
            fixture
                .runtime
                .approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| {
                    panic!("load reconstructed real adapter approval: {error}")
                })
                .unwrap_or_else(|| panic!("reconstructed real adapter approval missing"))
                .state(),
            ReplayReservationState::Reserved
        );
        assert_eq!(
            real_adapter_mutation_snapshot(&fixture.paths),
            [1, 1, 1, 0, 0]
        );
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 0);

        let execution_error = rejected(
            recreated.execute_prepared(&fixture.plan, reconstructed),
            "injected pre-effect failure must interrupt real adapter execution",
        );
        assert_eq!(execution_error.kind(), PortErrorKind::Unavailable);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 1);
        assert_eq!(
            fixture.runtime.executor.observed_commit_states(),
            vec![(
                AdmissionOperationState::DispatchCommitted,
                ReplayReservationState::Committed,
            )]
        );
        let committed_operation = fixture
            .runtime
            .admission_operations
            .load(&operation_id)
            .unwrap_or_else(|error| panic!("load committed real adapter operation: {error}"))
            .unwrap_or_else(|| panic!("committed real adapter operation missing"));
        assert_eq!(
            committed_operation.state(),
            AdmissionOperationState::DispatchCommitted
        );
        let committed_approval = fixture
            .runtime
            .approvals
            .get_approval_reservation(&operation_id)
            .unwrap_or_else(|error| panic!("load committed real adapter approval: {error}"))
            .unwrap_or_else(|| panic!("committed real adapter approval missing"));
        assert_eq!(
            committed_approval.state(),
            ReplayReservationState::Committed
        );
        assert_eq!(
            real_adapter_mutation_snapshot(&fixture.paths),
            [1, 1, 1, 0, 0]
        );
        let original_effects = Arc::clone(&fixture.runtime.effects);
        drop(recreated);
        drop(fixture.runtime);

        let cold = build_real_adapter_runtime(
            &fixture.paths,
            &fixture.operator_authority,
            &fixture.executor_signer,
            &fixture.submission_authority,
            &fixture.threshold_policy_authority,
            &fixture.threshold_requirement,
            &fixture.finding,
            fixture.plan.response_plan(),
            Arc::clone(&fixture.clock),
            false,
        );
        let resumed = cold
            .coordinator
            .resume_dispatch_committed(fixture.plan.response_plan(), &binding)
            .unwrap_or_else(|error| panic!("cold resume real adapter dispatch: {error}"));
        let AttestedFindingDispatchCommittedResume::Completed(resumed) = resumed else {
            panic!("cold real adapter resume did not recover completion");
        };
        assert_eq!(resumed.dispatch_id(), &binding.dispatch_id);
        assert_eq!(
            resumed.outcome(),
            AttestedFindingResponseCompletionOutcome::Activated
        );
        assert_eq!(original_effects.executions(), 0);
        assert_eq!(cold.effects.executions(), 1);
        assert_eq!(cold.executor.calls(), 1);
        assert_eq!(
            cold.executor.observed_commit_states(),
            vec![(
                AdmissionOperationState::DispatchCommitted,
                ReplayReservationState::Committed,
            )]
        );
        assert_eq!(
            original_effects
                .executions()
                .saturating_add(cold.effects.executions()),
            1
        );
        assert_eq!(
            cold.admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| panic!("cold load real adapter operation: {error}"))
                .unwrap_or_else(|| panic!("cold real adapter operation missing"))
                .state(),
            AdmissionOperationState::Completed
        );
        assert_eq!(
            cold.approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| panic!("cold load real adapter approval: {error}"))
                .unwrap_or_else(|| panic!("cold real adapter approval missing"))
                .state(),
            ReplayReservationState::Committed
        );
        assert_eq!(
            real_adapter_mutation_snapshot(&fixture.paths),
            [1, 1, 1, 0, 0]
        );
        let cold_effect_executions = cold.effects.executions();
        drop(cold);

        let replay = build_real_adapter_runtime(
            &fixture.paths,
            &fixture.operator_authority,
            &fixture.executor_signer,
            &fixture.submission_authority,
            &fixture.threshold_policy_authority,
            &fixture.threshold_requirement,
            &fixture.finding,
            fixture.plan.response_plan(),
            Arc::clone(&fixture.clock),
            false,
        );
        let replay_calls_before_resume = replay.executor.calls();
        assert_eq!(replay_calls_before_resume, 0);
        assert_eq!(replay.effects.executions(), 0);
        let replayed = replay
            .coordinator
            .resume_dispatch_committed(fixture.plan.response_plan(), &binding)
            .unwrap_or_else(|error| panic!("replay completed real adapter dispatch: {error}"));
        let AttestedFindingDispatchCommittedResume::Completed(replayed) = replayed else {
            panic!("completed real adapter replay lost terminal evidence");
        };
        assert_eq!(replayed.dispatch_id(), &binding.dispatch_id);
        assert_eq!(
            replayed.outcome(),
            AttestedFindingResponseCompletionOutcome::Activated
        );
        assert_eq!(replay.effects.executions(), 0);
        assert_eq!(
            replay.executor.calls(),
            replay_calls_before_resume.saturating_add(1)
        );
        assert_eq!(
            replay.executor.observed_commit_states(),
            vec![(
                AdmissionOperationState::Completed,
                ReplayReservationState::Committed,
            )]
        );
        assert_eq!(
            replay
                .admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| panic!("replay load real adapter operation: {error}"))
                .unwrap_or_else(|| panic!("replay real adapter operation missing"))
                .state(),
            AdmissionOperationState::Completed
        );
        assert_eq!(
            replay
                .approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| panic!("replay load real adapter approval: {error}"))
                .unwrap_or_else(|| panic!("replay real adapter approval missing"))
                .state(),
            ReplayReservationState::Committed
        );
        assert_eq!(
            original_effects
                .executions()
                .saturating_add(cold_effect_executions)
                .saturating_add(replay.effects.executions()),
            1
        );
    }
