#[test]
fn expired_governed_prepare_without_dispatch_compensates_and_closes_terminally() {
    let coordinator = setup_governed();
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };
    let operation_id = reservation.operation_id().to_string();
    let binding = prepared
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed dispatch binding");
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::ApprovalReserved)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("reserved approval lookup")
            .expect("reserved approval")
            .state(),
        ReplayReservationState::Reserved
    );
    assert!(coordinator
        .fixture
        .kernel
        .terminate_never_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
            Some(&coordinator.request),
        )
        .is_err());
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::ApprovalReserved)
    );

    let _expired_runtime = crate::scope_fixed_runtime_for_current_thread(
        coordinator
            .fixture
            .request
            .operator_capability()
            .expires_at
            .saturating_add(1),
        Vec::new(),
    );
    let mut tampered_binding = binding.clone();
    tampered_binding.policy_decision_hash = Digest32::new([0x9a; 32]);
    assert!(coordinator
        .fixture
        .kernel
        .terminate_never_committed_active_response(
            &coordinator.fixture.response_plan,
            &tampered_binding,
            None,
        )
        .is_err());
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::ApprovalReserved)
    );
    coordinator
        .fixture
        .kernel
        .terminate_never_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
            None,
        )
        .expect("expired never-dispatched governed response closes terminally");
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(&operation_id)
            .expect("cancelled approval lookup")
            .expect("cancelled approval")
            .state(),
        ReplayReservationState::Cancelled
    );
    let cleanup_actions = coordinator
        .operations
        .load_cleanup_actions(&operation_id)
        .expect("approval cleanup journal");
    assert!(cleanup_actions.iter().any(|action| {
        action.kind() == AdmissionCleanupActionKind::Approval
            && action.state() == AdmissionCleanupActionState::Completed
    }));
    coordinator
        .fixture
        .kernel
        .terminate_never_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
            None,
        )
        .expect("terminal governed cleanup is idempotent");
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn proposal_deadline_expiry_definitively_cancels_reserved_governed_dispatch() {
    let coordinator = setup_governed_with_stores_and_timeout(
        Arc::new(RecordingThresholdOperationStore::new()),
        Arc::new(DurableThresholdApprovalStore::new()),
        vec![Keypair::generate(), Keypair::generate()],
        1,
    );
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };
    let binding = prepared
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed binding");
    let proposal_deadline = coordinator
        .request
        .threshold_proposal()
        .expect("signed threshold proposal")
        .body()
        .proposal_deadline();
    let proposal_deadline_unix_ms = proposal_deadline
        .checked_mul(1_000)
        .expect("proposal deadline milliseconds");
    assert!(proposal_deadline_unix_ms < coordinator.fixture.response_plan.expires_at_unix_ms);
    assert!(
        proposal_deadline_unix_ms
            < coordinator
                .fixture
                .response_plan
                .operator_capability
                .expires_at_unix_ms
    );
    let _expired_proposal_runtime =
        crate::scope_fixed_runtime_for_current_thread(proposal_deadline, Vec::new());

    coordinator
        .fixture
        .kernel
        .terminate_never_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
            Some(&coordinator.request),
        )
        .expect("proposal expiry definitively closes reserved dispatch");
    assert_eq!(
        coordinator
            .operations
            .load(reservation.operation_id())
            .expect("operation lookup")
            .expect("compensated operation")
            .state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("cancelled approval")
            .state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn approval_token_expiry_definitively_cancels_reserved_governed_dispatch() {
    let coordinator = setup_governed_with_stores_and_token_timeout(
        Arc::new(RecordingThresholdOperationStore::new()),
        Arc::new(DurableThresholdApprovalStore::new()),
        vec![Keypair::generate(), Keypair::generate()],
        900,
        1,
    );
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };
    let binding = prepared
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed binding");
    let token_expiry = coordinator
        .request
        .approval_tokens()
        .first()
        .expect("governed approval token")
        .expires_at;
    let proposal_deadline = coordinator
        .request
        .threshold_proposal()
        .expect("signed threshold proposal")
        .body()
        .proposal_deadline();
    assert!(token_expiry < proposal_deadline);
    assert!(
        token_expiry
            .checked_mul(1_000)
            .expect("token expiry milliseconds")
            < coordinator.fixture.response_plan.expires_at_unix_ms
    );
    let _expired_token_runtime =
        crate::scope_fixed_runtime_for_current_thread(token_expiry, Vec::new());

    coordinator
        .fixture
        .kernel
        .terminate_never_committed_active_response(
            &coordinator.fixture.response_plan,
            &binding,
            Some(&coordinator.request),
        )
        .expect("approval token expiry definitively closes reserved dispatch");
    assert_eq!(
        coordinator
            .operations
            .load(reservation.operation_id())
            .expect("operation lookup")
            .expect("compensated operation")
            .state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("cancelled approval")
            .state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn governed_dispatch_gate_serializes_expired_termination_after_durable_commit() {
    let coordinator = setup_governed();
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed preparation");
    let binding = prepared
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed binding");
    let operation_id = match &prepared {
        PreparedActiveResponseAdmission::Governed(reservation) => {
            reservation.operation_id().to_string()
        }
        PreparedActiveResponseAdmission::Automatic(_) => {
            panic!("governed fixture must reserve approval")
        }
    };
    let response_plan = coordinator.fixture.response_plan.clone();
    let request = coordinator.request.clone();
    let executor = coordinator.executor_authority.clone();
    let operations = coordinator.operations.clone();
    let approvals = coordinator.approvals.clone();
    let kernel = Arc::new(coordinator.fixture.kernel);

    let (execution, termination, returned_before_dispatch) =
        race_expired_termination_against_inflight_dispatch(
            kernel,
            request,
            prepared,
            response_plan,
            binding,
            executor.clone(),
        );
    assert!(!returned_before_dispatch);
    assert!(execution.is_ok());
    assert!(termination.is_err());
    assert_eq!(executor.calls(), 1);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
    assert_eq!(
        approvals
            .get_approval_reservation(&operation_id)
            .expect("committed approval lookup")
            .expect("committed approval")
            .state(),
        ReplayReservationState::Committed
    );
}

#[test]
fn cancelled_approval_reservation_cannot_be_recovered_as_prepared() {
    let coordinator = setup_governed();
    let PreparedActiveResponseAdmission::Governed(reservation) = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation")
    else {
        panic!("governed policy must return a governed reservation");
    };
    coordinator
        .approvals
        .cancel_approval_reservation(reservation.operation_id())
        .expect("persist approval cancellation");

    assert!(coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .is_err());
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("cancelled approval reservation")
            .state(),
        ReplayReservationState::Cancelled
    );
    let cleanup_actions = coordinator
        .operations
        .load_cleanup_actions(reservation.operation_id())
        .expect("approval cleanup journal");
    assert!(cleanup_actions.iter().any(|action| {
        action.kind() == AdmissionCleanupActionKind::Approval
            && action.state() == AdmissionCleanupActionState::Completed
    }));
}

#[test]
fn cancellation_reason_is_sanitized_before_durable_compensation() {
    for reason in ["", "unsafe\0reason"] {
        let coordinator = setup_governed();
        let PreparedActiveResponseAdmission::Governed(reservation) = coordinator
            .fixture
            .kernel
            .prepare_active_response_admission(&coordinator.request)
            .expect("governed active-response reservation")
        else {
            panic!("governed policy must return a governed reservation");
        };

        coordinator
            .fixture
            .kernel
            .cancel_active_response_admission(&reservation, reason)
            .expect("sanitized active-response compensation");
        assert_eq!(
            coordinator.operations.states().last(),
            Some(&AdmissionOperationState::CompensatedBeforeDispatch)
        );
        assert_eq!(
            coordinator
                .approvals
                .get_approval_reservation(reservation.operation_id())
                .expect("approval lookup")
                .expect("cancelled approval reservation")
                .state(),
            ReplayReservationState::Cancelled
        );
    }
}

#[test]
fn unresolved_approval_reservation_blocks_authority_removal_until_compensation() {
    let mut coordinator = setup_governed();
    let PreparedActiveResponseAdmission::Governed(reservation) = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation")
    else {
        panic!("governed policy must return a governed reservation");
    };
    let original_approval_authority = Arc::clone(
        coordinator
            .fixture
            .kernel
            .approval_store
            .as_ref()
            .expect("installed approval authority"),
    );
    coordinator.fixture.kernel.clear_approval_store();

    let retained_approval_authority = coordinator
        .fixture
        .kernel
        .approval_store
        .as_ref()
        .expect("unresolved reservation must block approval authority removal");
    assert!(Arc::ptr_eq(
        retained_approval_authority,
        &original_approval_authority
    ));
    coordinator
        .fixture
        .kernel
        .cancel_active_response_admission(&reservation, "operator cancellation")
        .expect("retained original authority must complete durable compensation");
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("original approval lookup")
            .expect("original approval reservation")
            .state(),
        ReplayReservationState::Cancelled
    );
    let cleanup_actions = coordinator
        .operations
        .load_cleanup_actions(reservation.operation_id())
        .expect("approval cleanup journal");
    assert!(cleanup_actions.iter().any(|action| {
        action.kind() == AdmissionCleanupActionKind::Approval
            && action.state() == AdmissionCleanupActionState::Completed
    }));
}

#[test]
fn automatic_permit_is_invalid_after_same_subject_authority_replacement() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let first_authority = install_active_response_policy(&mut fixture, executor_signer.clone());
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("automatic active-response admission");
    fixture
        .kernel
        .set_admission_operation_store_handle(Arc::new(RecordingThresholdOperationStore::new()))
        .expect("rotation audit operation store");

    fixture.kernel.deactivate_governed_active_response_plans();
    let replacement = Arc::new(RecordingActiveResponseExecutor::new(executor_signer, 2));
    fixture
        .kernel
        .set_active_response_executor_authority(replacement.clone())
        .expect("same-subject replacement with a new durable generation");
    fixture
        .kernel
        .enable_governed_active_response_plans()
        .expect("reactivated active-response feature");

    assert!(fixture
        .kernel
        .execute_prepared_active_response(&request, &prepared)
        .is_err());
    assert_eq!(first_authority.calls(), 0);
    assert_eq!(replacement.calls(), 0);
}

#[test]
fn executor_authority_rotation_denies_while_governed_admission_is_nonterminal() {
    let mut coordinator = setup_governed();
    coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    coordinator
        .fixture
        .kernel
        .deactivate_governed_active_response_plans();
    let replacement = Arc::new(RecordingActiveResponseExecutor::new(
        coordinator.fixture.executor.clone(),
        2,
    ));

    assert!(coordinator
        .fixture
        .kernel
        .set_active_response_executor_authority(replacement)
        .is_err());
}

#[test]
fn executor_authority_rotation_allows_a_fully_completed_generation() {
    let mut coordinator = setup_governed();
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &prepared)
        .expect("governed active-response completion");
    coordinator
        .fixture
        .kernel
        .deactivate_governed_active_response_plans();
    let replacement = Arc::new(RecordingActiveResponseExecutor::new(
        coordinator.fixture.executor.clone(),
        2,
    ));

    coordinator
        .fixture
        .kernel
        .set_active_response_executor_authority(replacement)
        .expect("completed executor generation can rotate");
}

#[test]
fn revocation_between_reservation_and_commit_cancels_and_compensates() {
    let coordinator = setup_governed();
    let PreparedActiveResponseAdmission::Governed(reservation) = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation")
    else {
        panic!("governed policy must return a governed reservation");
    };
    let capability_id = coordinator.fixture.request.operator_capability().id.clone();
    coordinator
        .fixture
        .kernel
        .revoke_capability(&capability_id)
        .expect("operator capability revocation");

    assert!(coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, &reservation)
        .is_err());
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("cancelled approval reservation")
            .state(),
        ReplayReservationState::Cancelled
    );
}

#[test]
fn submitter_approval_is_rejected_before_operation_mutation() {
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    let approvals = Arc::new(DurableThresholdApprovalStore::new());
    let mut fixture = governed_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let artifacts = build_threshold_artifacts(
        &fixture,
        vec![fixture.submitter.clone(), Keypair::generate()],
    );
    install_threshold_authorities(&mut fixture, &artifacts, Arc::clone(&operations), approvals);
    let executor_signer = fixture.executor.clone();
    install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        Some(artifacts.proposal),
        artifacts.tokens,
    );

    assert!(fixture
        .kernel
        .prepare_active_response_admission(&request)
        .is_err());
    assert!(operations.states().is_empty());
}

#[test]
fn governed_admission_denies_without_durable_coordinator_stores() {
    let mut fixture = governed_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let artifacts =
        build_threshold_artifacts(&fixture, vec![Keypair::generate(), Keypair::generate()]);
    let requirement = artifacts.requirement.clone();
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("threshold requirement resolver");
    fixture
        .kernel
        .set_threshold_approval_policy_authority(artifacts.policy_authority.public_key())
        .expect("threshold proposal authority");
    assert!(fixture
        .kernel
        .enable_threshold_governed_approvals()
        .is_err());
    let policy_hash = fixture.kernel.config.policy_hash.clone();
    let policy_version = fixture.request.plan_body().policy_version.clone();
    let approval_requirement = fixture.request.plan_body().approval_requirement.clone();
    let ttl_ms = fixture.request.plan_body().ttl_ms;
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |_: &crate::kernel::ActiveResponsePolicyRequest, _: &str| {
                Ok(match &approval_requirement {
                    ResponseApprovalRequirement::Automatic => ActiveResponseRequirement::automatic(
                        policy_hash.clone(),
                        policy_version.clone(),
                        ttl_ms,
                        1_000,
                    ),
                    ResponseApprovalRequirement::Governed { policy_id } => {
                        ActiveResponseRequirement::governed(
                            policy_hash.clone(),
                            policy_version.clone(),
                            policy_id.clone(),
                            1_000,
                        )
                    }
                })
            },
        ))
        .expect("active-response requirement resolver");
    let executor = Arc::new(RecordingActiveResponseExecutor::new(
        fixture.executor.clone(),
        1,
    ));
    fixture
        .kernel
        .set_active_response_executor_authority(executor)
        .expect("active-response executor authority");
    let error = fixture
        .kernel
        .enable_governed_active_response_plans()
        .expect_err("active-response activation without a durable operation store must fail");
    assert!(error
        .to_string()
        .contains("durable admission operation store"));
}

#[test]
fn governed_admission_recovers_acknowledgement_loss_and_dispatch_commit() {
    let operations = Arc::new(RecordingThresholdOperationStore::with_ack_loss(
        AdmissionOperationState::ApprovalReserved,
    ));
    let approvals = Arc::new(DurableThresholdApprovalStore::with_ack_loss());
    let coordinator = setup_governed_with_stores(
        Arc::clone(&operations),
        Arc::clone(&approvals),
        vec![Keypair::generate(), Keypair::generate()],
    );

    let PreparedActiveResponseAdmission::Governed(first) = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("reservation acknowledgement recovery")
    else {
        panic!("governed policy must return a governed reservation");
    };
    let PreparedActiveResponseAdmission::Governed(recovered) = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("prepared admission recovery")
    else {
        panic!("governed policy must recover a governed reservation");
    };
    assert_eq!(first.operation_id(), recovered.operation_id());
    assert_eq!(
        operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::ApprovalReserved,
        ]
    );

    let first_permit = coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, &recovered)
        .expect("approval commit acknowledgement recovery");
    assert!(!first_permit.is_recovery());
    let recovery_permit = coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, &recovered)
        .expect("dispatch commitment recovery");
    assert!(recovery_permit.is_recovery());
    assert_eq!(
        first_permit.operation().operation_id(),
        recovery_permit.operation().operation_id()
    );
    assert_eq!(
        operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::DispatchCommitted)
            .count(),
        1
    );
    assert_eq!(
        approvals
            .get_approval_reservation(recovered.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Committed
    );
}

include!("committed_resume.rs");
