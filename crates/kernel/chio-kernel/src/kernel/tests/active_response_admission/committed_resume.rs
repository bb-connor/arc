struct ReadyColdPublicationIssuanceAuthority;

impl crate::kernel::CapabilityIssuanceAdmissionAuthority
    for ReadyColdPublicationIssuanceAuthority
{
    fn ensure_ready(&self) -> chio_security_types::ports::PortResult<()> {
        Ok(())
    }

    fn authorize(
        &self,
        _query: &chio_security_types::ports::IssuanceFreezeAdmissionQuery,
    ) -> chio_security_types::ports::PortResult<()> {
        Ok(())
    }
}

struct AllowColdPublicationPreDispatch;

impl crate::kernel::SecurityPreDispatchHook for AllowColdPublicationPreDispatch {
    fn name(&self) -> &str {
        "allow-cold-publication"
    }

    fn commit(
        &self,
        _context: &crate::kernel::SecurityPreDispatchContext<'_>,
    ) -> Result<Option<crate::kernel::SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

fn cold_publication(
    coordinator: &GovernedCoordinatorFixture,
    operation_store: Arc<dyn AdmissionOperationStore>,
    approval_store: Arc<dyn ApprovalStore>,
    budget_store: Arc<dyn crate::budget_store::BudgetStore>,
) -> crate::kernel::GovernedSecurityRuntimePublication {
    crate::kernel::GovernedSecurityRuntimePublication {
        active_response_requirement_resolver: coordinator
            .fixture
            .kernel
            .active_response_requirement_resolver
            .as_ref()
            .expect("active-response resolver")
            .clone(),
        threshold_approval_requirement_resolver: coordinator
            .fixture
            .kernel
            .threshold_approval_requirement_resolver
            .as_ref()
            .expect("threshold resolver")
            .clone(),
        admission_operation_store: operation_store,
        approval_store,
        budget_store,
        finding_authority: coordinator
            .fixture
            .kernel
            .active_response_finding_authority
            .as_ref()
            .expect("finding authority")
            .clone(),
        executor_authority: coordinator.executor_authority.clone(),
        capability_issuance_admission_authority: Arc::new(
            ReadyColdPublicationIssuanceAuthority,
        ),
        threshold_policy_authorities: coordinator
            .fixture
            .kernel
            .threshold_approval_policy_authorities
            .clone(),
        guards: Vec::new(),
        pre_dispatch_hook: Arc::new(AllowColdPublicationPreDispatch),
        post_invocation_pipeline: crate::post_invocation::PostInvocationPipeline::new(),
    }
}

fn governed_preparation(
    coordinator: &GovernedCoordinatorFixture,
) -> (
    PreparedActiveResponseAdmission,
    chio_security_types::ports::PreparedActiveResponseDispatchBinding,
    String,
) {
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response preparation");
    let operation_id = match &prepared {
        PreparedActiveResponseAdmission::Governed(reservation) => {
            reservation.operation_id().to_string()
        }
        PreparedActiveResponseAdmission::Automatic(_) => {
            panic!("governed fixture must reserve approval")
        }
    };
    let binding = prepared
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed dispatch binding");
    (prepared, binding, operation_id)
}

fn setup_automatic_for_recovery() -> (
    ActiveResponseFixture,
    ActiveResponseAdmissionRequest,
    Arc<RecordingActiveResponseExecutor>,
) {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let executor = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    (fixture, request, executor)
}

fn commit_operation_without_executor(
    coordinator: &GovernedCoordinatorFixture,
    operation_id: &str,
) {
    let operation = coordinator
        .operations
        .load(operation_id)
        .expect("operation lookup")
        .expect("prepared operation");
    let committed = coordinator
        .fixture
        .kernel
        .active_response_cas(
            &operation,
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
            None,
        )
        .expect("persist dispatch commitment");
    assert!(committed.applied);
    assert_eq!(
        committed.operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
}

fn commit_approval_without_operation(
    coordinator: &GovernedCoordinatorFixture,
    operation_id: &str,
) {
    let committed = coordinator
        .approvals
        .commit_approval_reservation(operation_id)
        .expect("commit approval without operation acknowledgement");
    assert_eq!(committed.operation_id(), operation_id);
    assert_eq!(committed.state(), ReplayReservationState::Committed);
    assert_eq!(
        coordinator
            .operations
            .load(operation_id)
            .expect("operation lookup")
            .expect("approval-reserved operation")
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
}

fn governed_binding_operation_version(
    binding: &chio_security_types::ports::PreparedActiveResponseDispatchBinding,
) -> u64 {
    match &binding.approval {
        ResponseDispatchApproval::Governed {
            admission_operation_version,
            ..
        } => *admission_operation_version,
        ResponseDispatchApproval::Automatic => panic!("governed durable binding"),
    }
}

#[test]
fn hot_prepare_rolls_committed_approval_forward_without_executor() {
    let coordinator = setup_governed();
    let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
    commit_approval_without_operation(&coordinator, &operation_id);

    let recovered = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("hot preparation recovers committed approval");
    let PreparedActiveResponseAdmission::Governed(_) = &recovered else {
        panic!("governed preparation must remain governed")
    };
    assert_eq!(
        recovered
            .durable_dispatch_binding(&coordinator.fixture.response_plan)
            .expect("recovered durable binding"),
        retained_binding
    );
    let operation = coordinator
        .operations
        .load(&operation_id)
        .expect("operation lookup")
        .expect("dispatch-committed operation");
    assert_eq!(operation.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(operation.dispatch_state(), AdmissionDispatchState::Committed);
    assert_eq!(
        operation.version(),
        governed_binding_operation_version(&retained_binding)
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn hot_reconstruction_rolls_committed_approval_forward_without_executor() {
    let coordinator = setup_governed();
    let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
    commit_approval_without_operation(&coordinator, &operation_id);
    coordinator
        .fixture
        .kernel
        .revoke_capability(&coordinator.fixture.request.operator_capability().id)
        .expect("post-commit capability revocation");

    assert!(matches!(
        coordinator
            .fixture
            .kernel
            .reconstruct_pre_dispatch_active_response_admission(
                &coordinator.request,
                &retained_binding,
            ),
        Ok(crate::kernel::PreDispatchActiveResponseReconstruction::NotPrepared)
    ));
    let operation = coordinator
        .operations
        .load(&operation_id)
        .expect("operation lookup")
        .expect("dispatch-committed operation");
    assert_eq!(operation.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(
        operation.version(),
        governed_binding_operation_version(&retained_binding)
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn same_live_resume_rolls_committed_approval_forward_after_expiry_and_executes_once() {
    let coordinator = setup_governed();
    let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
    commit_approval_without_operation(&coordinator, &operation_id);
    let expired_unix_secs = coordinator
        .fixture
        .response_plan
        .expires_at_unix_ms
        .checked_div(1_000)
        .expect("plan expiry seconds")
        .saturating_add(1);
    let _expired_runtime =
        crate::scope_fixed_runtime_for_current_thread(expired_unix_secs, Vec::new());

    let resumed = coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &coordinator.fixture.response_plan,
            &retained_binding,
        )
        .expect("resume committed approval after expiry");
    assert!(matches!(
        resumed,
        crate::kernel::DispatchCommittedActiveResponseResume::Completed(_)
    ));
    assert_eq!(coordinator.executor_authority.calls(), 1);
    assert_eq!(
        coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("completed operation")
            .state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("approval lookup")
            .expect("committed approval")
            .state(),
        ReplayReservationState::Committed
    );
}

#[test]
fn cold_recovery_rolls_committed_approval_forward_with_stable_binding() {
    let coordinator = setup_governed();
    let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
    commit_approval_without_operation(&coordinator, &operation_id);

    assert_eq!(
        coordinator
            .fixture
            .kernel
            .recover_nonterminal_admission_kind_with_authorities(
                coordinator.operations.as_ref(),
                coordinator.fixture.kernel.budget_store.as_ref(),
                Some(coordinator.approvals.as_ref()),
                AdmissionOperationKind::GovernedActiveResponse,
                retained_binding.executor_authority_id.as_str(),
            )
            .expect("cold governed recovery"),
        1
    );
    let operation = coordinator
        .operations
        .load(&operation_id)
        .expect("operation lookup")
        .expect("retained dispatch commitment");
    assert_eq!(operation.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(operation.dispatch_state(), AdmissionDispatchState::Committed);
    assert_eq!(
        operation.version(),
        governed_binding_operation_version(&retained_binding)
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn cold_recovery_retains_exact_dispatch_commitment_for_outbox_resume() {
    let coordinator = setup_governed();
    let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
    commit_approval_without_operation(&coordinator, &operation_id);
    commit_operation_without_executor(&coordinator, &operation_id);
    let before = coordinator
        .operations
        .load(&operation_id)
        .expect("operation lookup")
        .expect("dispatch commitment");

    assert_eq!(
        coordinator
            .fixture
            .kernel
            .recover_nonterminal_admission_kind_with_authorities(
                coordinator.operations.as_ref(),
                coordinator.fixture.kernel.budget_store.as_ref(),
                Some(coordinator.approvals.as_ref()),
                AdmissionOperationKind::GovernedActiveResponse,
                retained_binding.executor_authority_id.as_str(),
            )
            .expect("cold committed recovery"),
        1
    );
    assert_eq!(
        coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("retained dispatch commitment"),
        before
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn initial_cold_publication_retains_governed_commit_states_for_outbox_resume() {
    for dispatch_already_committed in [false, true] {
        let mut coordinator = setup_governed();
        let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
        commit_approval_without_operation(&coordinator, &operation_id);
        if dispatch_already_committed {
            commit_operation_without_executor(&coordinator, &operation_id);
        }
        let operation_store: Arc<dyn AdmissionOperationStore> = coordinator.operations.clone();
        let approval_store: Arc<dyn ApprovalStore> = coordinator.approvals.clone();
        let budget_store = coordinator.fixture.kernel.budget_store.clone();
        let publication = cold_publication(
            &coordinator,
            operation_store,
            approval_store,
            budget_store,
        );

        coordinator
            .fixture
            .kernel
            .deactivate_governed_active_response_plans();
        coordinator
            .fixture
            .kernel
            .deactivate_threshold_governed_approvals();
        coordinator
            .fixture
            .kernel
            .clear_active_response_executor_authority();
        coordinator
            .fixture
            .kernel
            .active_response_executor_generation_floor = 0;
        coordinator
            .fixture
            .kernel
            .publish_governed_security_runtime(publication)
            .expect("initial cold publication");

        let retained = coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("retained dispatch commitment");
        assert_eq!(retained.state(), AdmissionOperationState::DispatchCommitted);
        assert_eq!(retained.dispatch_state(), AdmissionDispatchState::Committed);
        assert_eq!(
            retained.version(),
            governed_binding_operation_version(&retained_binding)
        );
        let status = coordinator.fixture.kernel.governed_security_runtime_status();
        assert_eq!(status.publication_generation, 1);
        assert!(status.active_response_enabled);
        assert_eq!(coordinator.executor_authority.calls(), 0);
    }
}

#[test]
fn initial_cold_publication_compensates_governed_predispatch_rows() {
    for stop_at_prepared in [true, false] {
        let mut coordinator = setup_governed();
        let operation_id = if stop_at_prepared {
            let now_unix_ms = crate::kernel::current_unix_timestamp_ms();
            let verified = coordinator
                .fixture
                .kernel
                .verify_active_response_admission_with_authorized_at(
                    &coordinator.request,
                    now_unix_ms,
                    now_unix_ms,
                )
                .expect("governed admission verification");
            let crate::kernel::active_response_coordinator::VerifiedActiveResponseAdmission::Governed(
                verified,
            ) = verified
            else {
                panic!("governed fixture must verify governed admission")
            };
            let operation_id = verified.operation.operation_id().to_string();
            coordinator
                .operations
                .create_prepared((*verified.operation).clone())
                .expect("persist crash-point Prepared operation");
            operation_id
        } else {
            let (_, _, operation_id) = governed_preparation(&coordinator);
            operation_id
        };
        let operation_store: Arc<dyn AdmissionOperationStore> = coordinator.operations.clone();
        let approval_store: Arc<dyn ApprovalStore> = coordinator.approvals.clone();
        let budget_store = coordinator.fixture.kernel.budget_store.clone();
        let publication = cold_publication(
            &coordinator,
            operation_store,
            approval_store,
            budget_store,
        );

        coordinator
            .fixture
            .kernel
            .deactivate_governed_active_response_plans();
        coordinator
            .fixture
            .kernel
            .deactivate_threshold_governed_approvals();
        coordinator
            .fixture
            .kernel
            .clear_active_response_executor_authority();
        coordinator
            .fixture
            .kernel
            .active_response_executor_generation_floor = 0;
        coordinator
            .fixture
            .kernel
            .publish_governed_security_runtime(publication)
            .expect("initial cold publication compensates pre-dispatch work");

        assert_eq!(
            coordinator
                .operations
                .load(&operation_id)
                .expect("operation lookup")
                .expect("compensated operation")
                .state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert_eq!(
            coordinator
                .fixture
                .kernel
                .governed_security_runtime_status()
                .publication_generation,
            1
        );
        assert_eq!(coordinator.executor_authority.calls(), 0);
    }
}

#[test]
fn identical_authority_reinstallation_is_a_noop_with_unresolved_work() {
    let mut coordinator = setup_governed();
    let (_, _, operation_id) = governed_preparation(&coordinator);
    let operation_store: Arc<dyn AdmissionOperationStore> = coordinator.operations.clone();
    let approval_store: Arc<dyn ApprovalStore> = coordinator.approvals.clone();
    let budget_store = coordinator.fixture.kernel.budget_store.clone();

    coordinator
        .fixture
        .kernel
        .set_admission_operation_store_handle(operation_store)
        .expect("same operation authority is a no-op");
    coordinator
        .fixture
        .kernel
        .set_approval_store_handle(approval_store)
        .expect("same approval authority is a no-op");
    coordinator
        .fixture
        .kernel
        .set_budget_store_handle(budget_store)
        .expect("same budget authority is a no-op");
    assert_eq!(
        coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("unresolved operation")
            .state(),
        AdmissionOperationState::ApprovalReserved
    );

    coordinator
        .fixture
        .kernel
        .deactivate_governed_active_response_plans();
    coordinator
        .fixture
        .kernel
        .deactivate_threshold_governed_approvals();
    let error = coordinator
        .fixture
        .kernel
        .set_budget_store_handle(Arc::new(DurableThresholdBudgetStore::new()))
        .expect_err("different authority must not strand unresolved work");
    assert!(error.to_string().contains("would strand"));
}

#[test]
fn initial_publication_rejects_distinct_preinstalled_stores_with_unresolved_work() {
    let mut coordinator = setup_governed();
    let (_, _, operation_id) = governed_preparation(&coordinator);
    let candidate_operations: Arc<dyn AdmissionOperationStore> =
        Arc::new(RecordingThresholdOperationStore::new());
    let candidate_approvals: Arc<dyn ApprovalStore> =
        Arc::new(DurableThresholdApprovalStore::new());
    let candidate_budget: Arc<dyn crate::budget_store::BudgetStore> =
        Arc::new(DurableThresholdBudgetStore::new());
    let publication = cold_publication(
        &coordinator,
        candidate_operations,
        candidate_approvals,
        candidate_budget,
    );

    coordinator
        .fixture
        .kernel
        .deactivate_governed_active_response_plans();
    coordinator
        .fixture
        .kernel
        .deactivate_threshold_governed_approvals();
    coordinator
        .fixture
        .kernel
        .clear_active_response_executor_authority();
    coordinator
        .fixture
        .kernel
        .active_response_executor_generation_floor = 0;
    let error = coordinator
        .fixture
        .kernel
        .publish_governed_security_runtime(publication)
        .expect_err("distinct candidate stores must not replace unresolved authorities");
    assert!(error
        .to_string()
        .contains("admission authority replacement would strand"));
    assert_eq!(
        coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("unresolved operation")
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(
        coordinator
            .fixture
            .kernel
            .governed_security_runtime_status()
            .publication_generation,
        0
    );
}

#[test]
fn hot_prepare_rejects_mismatched_committed_approval_without_compensation() {
    let coordinator = setup_governed();
    let (_, _, operation_id) = governed_preparation(&coordinator);
    commit_approval_without_operation(&coordinator, &operation_id);
    coordinator
        .approvals
        .mismatch_approval_reservation_readback();

    let error = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect_err("mismatched committed approval must fail closed");
    assert!(error.to_string().contains("exact binding"));
    assert_eq!(
        coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("unchanged operation")
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn cold_recovery_rejects_mismatched_or_missing_committed_approval() {
    for missing in [false, true] {
        let coordinator = setup_governed();
        let (_, retained_binding, operation_id) = governed_preparation(&coordinator);
        commit_approval_without_operation(&coordinator, &operation_id);
        let before = coordinator
            .operations
            .load(&operation_id)
            .expect("operation lookup")
            .expect("approval-reserved operation");
        if missing {
            coordinator.approvals.hide_approval_reservation_readback();
        } else {
            coordinator
                .approvals
                .mismatch_approval_reservation_readback();
        }

        let error = coordinator
            .fixture
            .kernel
            .recover_nonterminal_admission_kind_with_authorities(
                coordinator.operations.as_ref(),
                coordinator.fixture.kernel.budget_store.as_ref(),
                Some(coordinator.approvals.as_ref()),
                AdmissionOperationKind::GovernedActiveResponse,
                retained_binding.executor_authority_id.as_str(),
            )
            .expect_err("invalid committed approval readback must fail closed");
        let expected = if missing { "is missing" } else { "exact binding" };
        assert!(error.to_string().contains(expected));
        assert_eq!(
            coordinator
                .operations
                .load(&operation_id)
                .expect("operation lookup")
                .expect("unchanged operation"),
            before
        );
        assert_eq!(coordinator.executor_authority.calls(), 0);
    }
}

#[test]
fn dispatch_committed_resume_uses_stable_binding_after_expiry_and_auth_rotation() {
    let mut coordinator = setup_governed();
    let (prepared, binding, operation_id) = governed_preparation(&coordinator);
    let reservation = match &prepared {
        PreparedActiveResponseAdmission::Governed(reservation) => reservation,
        PreparedActiveResponseAdmission::Automatic(_) => unreachable!(),
    };
    coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, reservation)
        .expect("persist operation and approval commitments");
    assert!(coordinator
        .executor_authority
        .load_committed_active_response_dispatch(
            &coordinator.fixture.response_plan.tenant_id,
            &binding.dispatch_id,
        )
        .expect("executor readback")
        .is_none());

    coordinator
        .fixture
        .kernel
        .revoke_capability(&coordinator.fixture.request.operator_capability().id)
        .expect("post-commit capability revocation");
    coordinator.fixture.kernel.deactivate_governed_active_response_plans();
    coordinator.fixture.finding_authority.set_ready(false);
    coordinator
        .fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            |_: &crate::kernel::ActiveResponsePolicyRequest, _: &str| {
                Err(ActiveResponsePolicyResolutionError::Invalid(
                    "rotated policy rejects historical admission".to_string(),
                ))
            },
        ))
        .expect("rotate active-response policy resolver");
    let expired_unix_secs = coordinator
        .fixture
        .response_plan
        .expires_at_unix_ms
        .checked_div(1_000)
        .expect("plan expiry seconds")
        .saturating_add(1);
    let _expired_runtime =
        crate::scope_fixed_runtime_for_current_thread(expired_unix_secs, Vec::new());

    let resumed = coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
        )
        .expect("post-expiry committed dispatch resume");
    let crate::kernel::DispatchCommittedActiveResponseResume::Completed(evidence) = resumed else {
        panic!("dispatch commitment must execute from its durable binding")
    };
    assert_eq!(evidence.dispatch_id(), &binding.dispatch_id);
    assert!(coordinator
        .executor_authority
        .last_dispatch_committed_resume());
    let retained = coordinator
        .executor_authority
        .committed_dispatches
        .lock()
        .expect("executor committed-dispatch lock")
        .get(&binding.dispatch_id)
        .cloned()
        .expect("resumed executor dispatch");
    assert_eq!(
        retained.authorization().body.authorized_at_unix_ms,
        binding.authorized_at_unix_ms
    );
    assert!(binding.authorized_at_unix_ms < coordinator.fixture.response_plan.expires_at_unix_ms);
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("approval lookup")
            .expect("committed approval")
            .state(),
        ReplayReservationState::Committed
    );
}

#[test]
fn dispatch_committed_resume_repairs_reserved_approval_before_executor_commit() {
    let coordinator = setup_governed();
    let (_, binding, operation_id) = governed_preparation(&coordinator);
    commit_operation_without_executor(&coordinator, &operation_id);
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("approval lookup")
            .expect("reserved approval")
            .state(),
        ReplayReservationState::Reserved
    );

    let resumed = coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
        )
        .expect("resume after operation CAS");
    assert!(matches!(
        resumed,
        crate::kernel::DispatchCommittedActiveResponseResume::Completed(_)
    ));
    assert_eq!(coordinator.executor_authority.calls(), 1);
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("approval lookup")
            .expect("repaired approval commitment")
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
}

#[test]
fn dispatch_committed_resume_is_typed_not_committed_before_irreversible_cas() {
    let (automatic, automatic_request, _) = setup_automatic_for_recovery();
    let automatic_prepared = automatic
        .kernel
        .prepare_active_response_admission(&automatic_request)
        .expect("automatic preparation");
    let automatic_binding = automatic_prepared
        .durable_dispatch_binding(&automatic.response_plan)
        .expect("durable automatic binding");
    assert!(matches!(
        automatic.kernel.resume_dispatch_committed_active_response(
            &automatic.response_plan,
            &automatic_binding,
        ),
        Ok(crate::kernel::DispatchCommittedActiveResponseResume::NotDispatchCommitted)
    ));

    let governed = setup_governed();
    let (_, governed_binding, _) = governed_preparation(&governed);
    assert!(matches!(
        governed.fixture.kernel.resume_dispatch_committed_active_response(
            &governed.fixture.response_plan,
            &governed_binding,
        ),
        Ok(crate::kernel::DispatchCommittedActiveResponseResume::NotDispatchCommitted)
    ));
    assert_eq!(governed.executor_authority.calls(), 0);
}

#[test]
fn automatic_prepared_execution_rederives_stable_dispatch_after_clock_advance() {
    let (fixture, request, executor) = setup_automatic_for_recovery();
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("automatic preparation");
    let binding = prepared
        .durable_dispatch_binding(&fixture.response_plan)
        .expect("durable automatic binding");
    let advanced_unix_secs = fixture
        .request
        .operator_capability()
        .issued_at
        .saturating_add(1);
    let _advanced_runtime =
        crate::scope_fixed_runtime_for_current_thread(advanced_unix_secs, Vec::new());

    let evidence = fixture
        .kernel
        .execute_prepared_active_response(&request, &prepared)
        .expect("execute automatic preparation after clock advance");
    assert_eq!(evidence.dispatch_id(), &binding.dispatch_id);
    assert_eq!(
        evidence.dispatch_authorization().body.authorized_at_unix_ms,
        binding.authorized_at_unix_ms
    );
    assert!(!executor.last_dispatch_committed_resume());
}

#[test]
fn governed_prepared_execution_uses_retained_time_after_live_reverification() {
    let coordinator = setup_governed();
    let (prepared, binding, _) = governed_preparation(&coordinator);
    let advanced_unix_secs = coordinator
        .fixture
        .request
        .operator_capability()
        .issued_at
        .saturating_add(1);
    let _advanced_runtime =
        crate::scope_fixed_runtime_for_current_thread(advanced_unix_secs, Vec::new());

    let evidence = coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &prepared)
        .expect("execute governed preparation after clock advance");
    assert_eq!(evidence.dispatch_id(), &binding.dispatch_id);
    assert_eq!(
        evidence.dispatch_authorization().body.authorized_at_unix_ms,
        binding.authorized_at_unix_ms
    );
}

#[test]
fn retained_pre_dispatch_reconstruction_live_verifies_and_preserves_exact_binding() {
    {
        let (fixture, request, _) = setup_automatic_for_recovery();
        let initial = fixture
            .kernel
            .prepare_active_response_admission(&request)
            .expect("initial automatic preparation");
        let binding = initial
            .durable_dispatch_binding(&fixture.response_plan)
            .expect("retained automatic binding");
        let advanced_unix_secs = fixture
            .request
            .operator_capability()
            .issued_at
            .saturating_add(1);
        let _advanced_runtime =
            crate::scope_fixed_runtime_for_current_thread(advanced_unix_secs, Vec::new());
        let reconstructed = fixture
            .kernel
            .reconstruct_pre_dispatch_active_response_admission(&request, &binding)
            .expect("live automatic reconstruction");
        let crate::kernel::PreDispatchActiveResponseReconstruction::Prepared(reconstructed) =
            reconstructed
        else {
            panic!("automatic preparation must remain pre-dispatch")
        };
        assert_eq!(
            reconstructed
                .durable_dispatch_binding(&fixture.response_plan)
                .expect("reconstructed automatic binding"),
            binding
        );
    }

    {
        let coordinator = setup_governed();
        let (_, binding, _) = governed_preparation(&coordinator);
        let advanced_unix_secs = coordinator
            .fixture
            .request
            .operator_capability()
            .issued_at
            .saturating_add(1);
        let _advanced_runtime =
            crate::scope_fixed_runtime_for_current_thread(advanced_unix_secs, Vec::new());
        let reconstructed = coordinator
            .fixture
            .kernel
            .reconstruct_pre_dispatch_active_response_admission(
                &coordinator.request,
                &binding,
            )
            .expect("live governed reconstruction");
        let crate::kernel::PreDispatchActiveResponseReconstruction::Prepared(reconstructed) =
            reconstructed
        else {
            panic!("approval-reserved operation must remain pre-dispatch")
        };
        assert_eq!(
            reconstructed
                .durable_dispatch_binding(&coordinator.fixture.response_plan)
                .expect("reconstructed governed binding"),
            binding
        );
    }
}

#[test]
fn retained_pre_dispatch_reconstruction_never_bypasses_live_denial() {
    let (fixture, request, _) = setup_automatic_for_recovery();
    let initial = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("initial automatic preparation");
    let binding = initial
        .durable_dispatch_binding(&fixture.response_plan)
        .expect("retained automatic binding");
    fixture
        .kernel
        .revoke_capability(&fixture.request.operator_capability().id)
        .expect("revoke retained capability");

    assert!(fixture
        .kernel
        .reconstruct_pre_dispatch_active_response_admission(&request, &binding)
        .is_err());
}

#[test]
fn retained_pre_dispatch_reconstruction_observes_intervening_dispatch_commit() {
    let coordinator = setup_governed();
    let (_, binding, operation_id) = governed_preparation(&coordinator);
    commit_operation_without_executor(&coordinator, &operation_id);

    assert!(matches!(
        coordinator
            .fixture
            .kernel
            .reconstruct_pre_dispatch_active_response_admission(
                &coordinator.request,
                &binding,
            ),
        Ok(crate::kernel::PreDispatchActiveResponseReconstruction::NotPrepared)
    ));
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn dispatch_committed_resume_rejects_tampered_and_cross_dispatch_bindings() {
    let coordinator = setup_governed();
    let (_, binding, operation_id) = governed_preparation(&coordinator);
    commit_operation_without_executor(&coordinator, &operation_id);

    let mut tampered = binding.clone();
    tampered.authorized_at_unix_ms = tampered.authorized_at_unix_ms.saturating_add(1);
    assert!(tampered.authorized_at_unix_ms < coordinator.fixture.response_plan.expires_at_unix_ms);
    assert_eq!(tampered.dispatch_id, binding.dispatch_id);
    assert!(coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &coordinator.fixture.response_plan,
            &tampered,
        )
        .is_err());

    let other = setup_governed();
    let (_, other_binding, _) = governed_preparation(&other);
    let mut cross_dispatch = binding;
    assert_ne!(cross_dispatch.dispatch_id, other_binding.dispatch_id);
    cross_dispatch.dispatch_id = other_binding.dispatch_id;
    assert!(coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &coordinator.fixture.response_plan,
            &cross_dispatch,
        )
        .is_err());
    assert_eq!(coordinator.executor_authority.calls(), 0);
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::DispatchCommitted)
    );
}

#[test]
fn committed_operation_anchor_rejects_self_consistent_plan_and_dispatch_substitution() {
    let coordinator = setup_governed();
    let (_, binding, operation_id) = governed_preparation(&coordinator);
    commit_operation_without_executor(&coordinator, &operation_id);

    let mut substituted_plan = coordinator.fixture.response_plan.clone();
    substituted_plan.effects = PlannedResponseEffects::new(vec![active_response_planned_effect(
        &substituted_plan.action_id,
        ResponseEffectKind::ThrottleSession,
        0,
        substituted_plan.affected_set_hash,
    )])
    .expect("substituted response effects");
    let authorization_body = serde_json::to_value(substituted_plan.authorization_body())
        .expect("substituted authorization body");
    let substituted_plan_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(
        &authorization_body,
    )
    .expect("substituted plan hash");
    substituted_plan.plan_hash = active_response_digest_from_hex(&substituted_plan_hash);

    let mut substituted_binding = binding;
    substituted_binding.plan_hash = substituted_plan.plan_hash;
    substituted_binding.authorized_at_unix_ms =
        substituted_binding.authorized_at_unix_ms.saturating_add(1);
    substituted_binding.governed_intent_hash = Digest32::new([0xb4; 32]);
    substituted_binding.policy_decision_hash = Digest32::new([0xb5; 32]);
    let approval = match &substituted_binding.approval {
        ResponseDispatchApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } => ActiveResponseExecutionApproval::Governed {
            admission_operation_id: admission_operation_id.as_str().to_string(),
            admission_operation_version: *admission_operation_version,
            approval_set_hash: active_response_hex(approval_set_hash),
        },
        ResponseDispatchApproval::Automatic => panic!("governed binding approval"),
    };
    substituted_binding.dispatch_id =
        crate::derive_active_response_dispatch_id(
            &substituted_plan,
            &coordinator.executor_authority.identity(),
            &active_response_hex(&substituted_binding.authorization_capability_hash),
            &active_response_hex(&substituted_binding.governed_intent_hash),
            &active_response_hex(&substituted_binding.policy_decision_hash),
            substituted_binding.authorized_at_unix_ms,
            &approval,
        )
        .expect("self-consistent substituted dispatch id");
    substituted_binding
        .validate_for_plan(&substituted_plan)
        .expect("self-consistent substituted binding");

    assert!(coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &substituted_plan,
            &substituted_binding,
        )
        .is_err());
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn completed_operation_without_executor_dispatch_fails_closed() {
    let coordinator = setup_governed();
    let (prepared, binding, operation_id) = governed_preparation(&coordinator);
    let reservation = match &prepared {
        PreparedActiveResponseAdmission::Governed(reservation) => reservation,
        PreparedActiveResponseAdmission::Automatic(_) => unreachable!(),
    };
    coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, reservation)
        .expect("commit governed dispatch");
    let committed = coordinator
        .operations
        .load(&operation_id)
        .expect("operation lookup")
        .expect("committed operation");
    let legacy_completed = committed
        .transition_checked(
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            committed.coordinator_lease_epoch(),
            None,
        )
        .expect("construct legacy terminal projection");
    coordinator
        .operations
        .inject_legacy_operation_without_outbox(legacy_completed);

    let error = coordinator
        .fixture
        .kernel
        .resume_dispatch_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
        )
        .expect_err("completed operation without executor record must fail closed");
    assert!(error
        .to_string()
        .contains("lacks its executor dispatch record"));
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn dispatch_commit_reloads_operation_anchor_before_irreversible_cas() {
    let coordinator = setup_governed();
    let (prepared, _, _) = governed_preparation(&coordinator);
    let reservation = match &prepared {
        PreparedActiveResponseAdmission::Governed(reservation) => reservation,
        PreparedActiveResponseAdmission::Automatic(_) => unreachable!(),
    };
    coordinator.operations.hide_cleanup_actions();

    let error = coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, reservation)
        .expect_err("missing operation anchor must block dispatch commitment");
    assert!(error.to_string().contains("dispatch anchor"));
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::ApprovalReserved)
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn policy_decision_rotation_compensates_stale_pre_dispatch_anchor() {
    let mut coordinator = setup_governed();
    let (_, _, operation_id) = governed_preparation(&coordinator);
    let policy_hash = coordinator.fixture.kernel.config.policy_hash.clone();
    let policy_version = coordinator.fixture.response_plan.policy_version.clone();
    let ResponseApprovalRequirement::Governed { policy_id } =
        &coordinator.fixture.response_plan.approval_requirement
    else {
        unreachable!()
    };
    let policy_id = policy_id.clone();
    coordinator.fixture.kernel.active_response_requirement_resolver = Some(Arc::new(
        move |_: &crate::kernel::ActiveResponsePolicyRequest, _: &str| {
            Ok(ActiveResponseRequirement::governed(
                policy_hash.clone(),
                policy_version.clone(),
                policy_id.clone(),
                2_000,
            ))
        },
    ));

    let error = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect_err("rotated policy decision must stale the retained preparation");
    assert!(error.to_string().contains("preparation is stale"));
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("approval lookup")
            .expect("cancelled approval")
            .state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn operation_anchor_creation_failure_compensates_the_created_operation() {
    let coordinator = setup_governed();
    coordinator.operations.fail_next_cleanup_creation();

    let error = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect_err("anchor creation failure must stop preparation");
    assert!(error
        .to_string()
        .contains("injected cleanup creation failure"));
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    let operations = coordinator
        .operations
        .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 1)
        .expect("terminal operation inventory");
    assert!(operations.is_empty());
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn operation_anchor_create_ack_loss_recovers_one_anchor_and_one_reservation() {
    let coordinator = setup_governed();
    coordinator.operations.lose_next_cleanup_create_ack();

    let (_, _, operation_id) = governed_preparation(&coordinator);
    let actions = coordinator
        .operations
        .load_cleanup_actions(&operation_id)
        .expect("anchor cleanup lookup");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind(), AdmissionCleanupActionKind::Approval);
    assert_eq!(coordinator.approvals.reserve_calls(), 1);
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Reserved
    );
}

#[test]
fn cleanup_cancellation_tombstone_fences_a_late_active_response_reserve() {
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    let barrier = Arc::new(Barrier::new(2));
    let approvals = Arc::new(DurableThresholdApprovalStore::with_blocked_first_reserve(
        Arc::clone(&barrier),
    ));
    let coordinator = setup_governed_with_stores(
        Arc::clone(&operations),
        Arc::clone(&approvals),
        vec![Keypair::generate(), Keypair::generate()],
    );
    let request = coordinator.request.clone();
    let kernel = Arc::new(coordinator.fixture.kernel);

    std::thread::scope(|scope| {
        let dispatch_kernel = Arc::clone(&kernel);
        let handle = scope.spawn(move || {
            dispatch_kernel.prepare_active_response_admission(&request)
        });
        barrier.wait();
        let operation = operations
            .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 1)
            .expect("unresolved operation lookup")
            .into_iter()
            .next()
            .expect("prepared active-response operation");
        kernel
            .claim_pre_dispatch_compensation(
                operation.operation_id(),
                "deterministic late-reserve race",
            )
            .expect("claim pre-dispatch cleanup")
            .expect("cleanup wins before dispatch");
        assert_eq!(
            approvals
                .get_approval_reservation(operation.operation_id())
                .expect("approval tombstone lookup")
                .expect("approval cancellation tombstone")
                .state(),
            ReplayReservationState::Cancelled
        );
        barrier.wait();
        handle
            .join()
            .expect("late reserve thread")
            .expect_err("late reserve must observe the cancellation tombstone");
    });

    assert_eq!(approvals.reserve_calls(), 2);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    let operation = operations
        .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 1)
        .expect("terminal operation inventory");
    assert!(operation.is_empty());
}
