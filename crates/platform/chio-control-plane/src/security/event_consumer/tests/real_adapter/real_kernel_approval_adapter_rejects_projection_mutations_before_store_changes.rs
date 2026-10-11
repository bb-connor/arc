use super::*;

#[test]
fn real_kernel_approval_adapter_rejects_projection_mutations_before_store_changes() {
    type ApprovalMutation = fn(&mut GovernedApprovalRequest);

    let fixture = real_adapter_fixture();
    let baseline = real_adapter_mutation_snapshot(&fixture.paths);
    let zero_budget_and_replay = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    assert_eq!(zero_budget_and_replay, [0; 9]);
    let cases: [(&str, ApprovalMutation); 6] = [
        ("proposal_digest", mutate_real_adapter_proposal_digest),
        ("proposal_deadline", mutate_real_adapter_proposal_deadline),
        ("capability_digest", mutate_real_adapter_capability_digest),
        ("governed_intent", mutate_real_adapter_governed_intent),
        ("artifact_ref", mutate_real_adapter_artifact_ref),
        ("artifact_digest", mutate_real_adapter_artifact_digest),
    ];
    for (name, mutate) in cases {
        let mut substituted = fixture.governed_request().clone();
        mutate(&mut substituted);
        let verifier = KernelActiveResponseApprovalVerifier::for_prepare(
            fixture.runtime.kernel.as_ref(),
            &substituted,
            fixture.native_request(),
        );
        let error = rejected(
            verifier.verify_and_reserve(&substituted),
            "substituted real adapter projection must fail closed",
        );
        assert_eq!(
            error.kind(),
            PortErrorKind::IntegrityFailure,
            "unexpected error for {name} substitution"
        );
        assert_eq!(
            real_adapter_mutation_snapshot(&fixture.paths),
            baseline,
            "{name} substitution mutated a durable authority"
        );
        assert_eq!(
            real_adapter_budget_and_replay_snapshot(&fixture.paths),
            zero_budget_and_replay,
            "{name} substitution mutated a budget or replay authority"
        );
    }
    assert_eq!(baseline, [0, 0, 0, 0, 0]);
    assert_eq!(fixture.runtime.effects.executions(), 0);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert!(fixture
        .runtime
        .admission_operations
        .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 8)
        .unwrap_or_else(|error| panic!("list real adapter mutation operations: {error}"))
        .is_empty());

    let prepared = fixture
        .runtime
        .coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone())
        .unwrap_or_else(|error| panic!("prepare scoped mutation fixture: {error}"));
    let operation_id = real_adapter_prepared_operation_id(&prepared);
    let PreparedAttestedFindingResponse::Kernel(kernel_prepared) = &prepared else {
        panic!("scoped mutation fixture must retain a kernel preparation");
    };
    let retained = kernel_prepared
        .test_governed_approval()
        .as_ref()
        .cloned()
        .unwrap_or_else(|| panic!("scoped mutation fixture reservation missing"));
    let prepared_native = kernel_prepared.test_prepared().clone();
    let reserved_baseline = real_adapter_mutation_snapshot(&fixture.paths);
    let reserved_budget_and_replay = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    assert_eq!(reserved_baseline, [1, 1, 1, 0, 0]);
    assert_eq!(reserved_budget_and_replay, [1, 1, 0, 0, 0, 0, 0, 0, 0]);

    for (name, mutate) in cases {
        let mut substituted = fixture.governed_request().clone();
        mutate(&mut substituted);
        let mut substituted_reservation = retained.clone();
        substituted_reservation.request = substituted.clone();
        substituted_reservation.expires_at_unix_ms = substituted.proposal_expires_at_unix_ms;

        let reconstruct = KernelActiveResponseApprovalVerifier::for_reconstruction(
            fixture.runtime.kernel.as_ref(),
            &substituted,
            fixture.native_request(),
        );
        let reconstruct_error = rejected(
            reconstruct.reconstruct(&substituted, &substituted_reservation),
            "substituted reconstruction projection must fail closed",
        );
        assert_eq!(
            reconstruct_error.kind(),
            PortErrorKind::IntegrityFailure,
            "unexpected reconstruction error for {name} substitution"
        );

        let mutation = GovernedApprovalReservationMutation {
            reservation: substituted_reservation,
        };
        let commit = KernelActiveResponseApprovalVerifier::for_commit(
            fixture.runtime.kernel.as_ref(),
            &substituted,
            fixture.native_request(),
            prepared_native.clone(),
        );
        let commit_error = rejected(
            commit.commit(&mutation),
            "substituted commit projection must fail closed",
        );
        assert_eq!(
            commit_error.kind(),
            PortErrorKind::IntegrityFailure,
            "unexpected commit error for {name} substitution"
        );

        let cancel = KernelActiveResponseApprovalVerifier::for_cancel(
            fixture.runtime.kernel.as_ref(),
            &substituted,
            fixture.native_request(),
            prepared_native.clone(),
        );
        let cancel_error = rejected(
            cancel.cancel(&mutation),
            "substituted cancel projection must fail closed",
        );
        assert_eq!(
            cancel_error.kind(),
            PortErrorKind::IntegrityFailure,
            "unexpected cancel error for {name} substitution"
        );
        assert_eq!(
            real_adapter_mutation_snapshot(&fixture.paths),
            reserved_baseline,
            "scoped {name} substitution mutated a durable authority"
        );
        assert_eq!(
            real_adapter_budget_and_replay_snapshot(&fixture.paths),
            reserved_budget_and_replay,
            "scoped {name} substitution mutated a budget or replay authority"
        );
    }
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(&operation_id)
            .unwrap_or_else(|error| panic!("load scoped mutation operation: {error}"))
            .unwrap_or_else(|| panic!("scoped mutation operation missing"))
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(&operation_id)
            .unwrap_or_else(|error| panic!("load scoped mutation approval: {error}"))
            .unwrap_or_else(|| panic!("scoped mutation approval missing"))
            .state(),
        ReplayReservationState::Reserved
    );
    assert_eq!(fixture.runtime.effects.executions(), 0);
    assert_eq!(fixture.runtime.executor.calls(), 0);
}
