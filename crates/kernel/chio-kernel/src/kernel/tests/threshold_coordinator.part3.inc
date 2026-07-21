#[test]
fn threshold_coordinator_issues_one_dispatch_permit_under_race() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    let kernel = std::sync::Arc::new(kernel);
    let coordinator_authority_id = format!("kernel:{}", kernel.public_key().to_hex());
    let prepared = prepared_threshold_coordinator_admission_for_authority(
        &coordinator_authority_id,
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let spawn = |prepared: crate::threshold_approval::PreparedGovernedToolAdmission| {
        let kernel = std::sync::Arc::clone(&kernel);
        let barrier = std::sync::Arc::clone(&barrier);
        let request = request.clone();
        let capability = capability.clone();
        let grant = grant.clone();
        std::thread::spawn(move || {
            barrier.wait();
            kernel.coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        })
    };
    let first = spawn(prepared.clone());
    let second = spawn(prepared);
    barrier.wait();
    let results = [
        first.join().expect("first join"),
        second.join().expect("second join"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::DispatchCommitted)
            .count(),
        1
    );
}

#[test]
fn dropped_threshold_dispatch_is_terminalized_unknown() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    let coordinator_authority_id = format!("kernel:{}", kernel.public_key().to_hex());
    let prepared = prepared_threshold_coordinator_admission_for_authority(
        &coordinator_authority_id,
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let (permit, budget_mutation) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("dispatch permit");
    let operation_id = permit.operation_id().to_string();
    {
        let mut guard = PostAdmissionDropGuard::new(
            &kernel,
            &request,
            &capability,
            Some(0),
            &budget_mutation,
            None,
            PostAdmissionReceiptContext {
                extra_metadata: None,
                pre_invocation_guard_evidence: Vec::new(),
            },
            false,
        );
        guard.bind_threshold_operation(permit.operation().clone());
        guard.mark_dispatch_started();
    }
    assert_eq!(
        operations
            .load(&operation_id)
            .expect("operation load")
            .expect("operation")
            .state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    let usage = budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("budget usage");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
}
