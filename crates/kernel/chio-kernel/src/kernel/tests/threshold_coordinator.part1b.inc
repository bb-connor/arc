#[tokio::test]
async fn top_level_threshold_dispatch_uses_durable_coordinator_to_completion() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel.register_tool_server(Box::new(EchoServer::new("payments", vec!["transfer"])));
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("threshold tool response");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionOperationState::PaymentAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
            AdmissionOperationState::DispatchCommitted,
            AdmissionOperationState::Completed,
        ]
    );
    assert_signed_receipt_matches_terminal_operation(
        &response,
        &operations,
        AdmissionOperationState::Completed,
    );
}

#[tokio::test]
async fn top_level_legacy_compensation_returns_signed_durable_deny() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "legacy-top-level-compensated-deny".to_string();
    let (operations, approvals, budget, invocations) =
        install_legacy_nonce_reservation_failure(
            &mut kernel,
            &capability,
            &intent,
            &mut request,
            now,
            "legacy-top-level-compensated-token",
        );

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("compensated top-level admission must return a signed denial");

    assert_legacy_nonce_failure_compensation(
        &response,
        &capability,
        request.approval_token.as_ref().expect("legacy approval token"),
        &operations,
        &approvals,
        &budget,
        &invocations,
    );
}

#[tokio::test]
async fn nested_legacy_compensation_returns_signed_durable_deny() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "legacy-nested-compensated-deny".to_string();
    let (operations, approvals, budget, invocations) =
        install_legacy_nonce_reservation_failure(
            &mut kernel,
            &capability,
            &intent,
            &mut request,
            now,
            "legacy-nested-compensated-token",
        );
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![capability.clone()])
        .expect("session");
    kernel
        .activate_session(&session_id)
        .expect("active session");
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .expect("session request");
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
        .await
        .expect("compensated nested admission must return a signed denial");

    assert_legacy_nonce_failure_compensation(
        &response,
        &capability,
        request.approval_token.as_ref().expect("legacy approval token"),
        &operations,
        &approvals,
        &budget,
        &invocations,
    );
}

#[tokio::test]
async fn legacy_approval_replay_after_kernel_restart_never_redispatches() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.approval_token = Some(legacy_threshold_test_token(
        &kernel,
        &capability,
        &intent,
        &request.request_id,
        "legacy-restart-token",
        now,
    ));
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals.clone())
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("first legacy governed response");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_signed_receipt_matches_terminal_operation(
        &response,
        &operations,
        AdmissionOperationState::Completed,
    );
    let operation_id = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.pointer("/protocol_admission/admission_operation/operation_id")
        })
        .and_then(serde_json::Value::as_str)
        .expect("signed operation id")
        .to_string();
    let terminal_before_restart = operations
        .load(&operation_id)
        .expect("operation load")
        .expect("terminal operation");
    let committed_tombstone_before_restart = approvals
        .get_approval_reservation(&operation_id)
        .expect("approval lookup")
        .expect("approval tombstone");
    assert_eq!(
        committed_tombstone_before_restart.state(),
        ReplayReservationState::Committed
    );
    let expected_token = request.approval_token.as_ref().expect("legacy approval token");
    let expected_token_digest = expected_token.token_digest().expect("legacy token digest");
    assert_eq!(committed_tombstone_before_restart.approval_set().members().len(), 1);
    assert_eq!(
        committed_tombstone_before_restart.approval_set().members()[0].token_id(),
        expected_token.id.as_str()
    );
    assert_eq!(
        committed_tombstone_before_restart.approval_set().members()[0].token_digest(),
        expected_token_digest.as_str()
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let restart_keypair = kernel.config.keypair.clone();
    let restart_policy_hash = kernel.config.policy_hash.clone();
    drop(kernel);
    let mut restart_config = make_config();
    restart_config.keypair = restart_keypair;
    restart_config.policy_hash = restart_policy_hash;
    let mut restarted = make_kernel(restart_config);
    restarted.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    restarted
        .set_admission_operation_store_handle(operations.clone())
        .expect("restarted operation store");
    restarted
        .set_approval_store_handle(approvals.clone())
        .expect("restarted approval store");
    restarted
        .set_budget_store_handle(budget.clone())
        .expect("restarted budget store");

    let replay = restarted
        .evaluate_tool_call(&request)
        .await
        .expect_err("committed legacy approval replay must fail closed");
    assert!(replay.to_string().contains("already completed"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let terminal_after_restart = operations
        .load(&operation_id)
        .expect("restarted operation load")
        .expect("restarted terminal operation");
    assert_eq!(terminal_after_restart, terminal_before_restart);
    assert_eq!(
        approvals
            .get_approval_reservation(&operation_id)
            .expect("restarted approval lookup")
            .expect("restarted approval tombstone"),
        committed_tombstone_before_restart
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("captured usage")
            .invocation_count,
        1
    );
}

#[tokio::test]
async fn legacy_approval_restart_after_dispatch_commit_never_redispatches() {
    let (mut kernel, capability, grant, intent, mut request, now) = threshold_test_fixture();
    let token = legacy_threshold_test_token(
        &kernel,
        &capability,
        &intent,
        &request.request_id,
        "legacy-dispatch-commit-token",
        now,
    );
    request.approval_token = Some(token.clone());
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals.clone())
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");

    let capability_hash = crate::threshold_approval::authorization_capability_hash(&capability)
        .expect("capability hash");
    let intent_hash = intent.binding_hash().expect("intent hash");
    let verified =
        crate::threshold_approval::VerifiedGovernedApprovalAdmission::from_legacy_token(
            &token,
            &capability_hash,
            &intent_hash,
            &kernel.config.policy_hash,
        )
        .expect("normalized legacy approval");
    let protocol = kernel
        .prepare_threshold_protocol_admission(&request, &capability, 0, now)
        .expect("protocol preparation");
    let coordinator_authority_id = format!("kernel:{}", kernel.public_key().to_hex());
    let prepared = crate::threshold_approval::prepare_governed_tool_admission_operation(
        crate::threshold_approval::GovernedToolAdmissionOperationInput {
            coordinator_authority_id: &coordinator_authority_id,
            request_id: &request.request_id,
            capability_id: &capability.id,
            authorization_capability_hash: &capability_hash,
            arguments: &request.arguments,
            governed_intent_hash: &intent_hash,
            policy_hash: &kernel.config.policy_hash,
            verified_approval: &verified,
            broker_attempt_id: protocol.broker_attempt_id(),
            budget_hold_id: Some(protocol.hold_id()),
            supplemental_authorization_reference: None,
            supplemental_authorization_digest: None,
            execution_nonce_id: None,
            coordinator_lease_epoch: 1,
        },
    )
    .expect("prepared legacy admission");
    let (permit, _mutation) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("dispatch-committed legacy admission");
    let operation_id = permit.operation_id().to_string();
    let committed_before_restart = operations
        .load(&operation_id)
        .expect("operation load")
        .expect("committed operation");
    assert_eq!(
        committed_before_restart.state(),
        AdmissionOperationState::DispatchCommitted
    );
    let committed_tombstone_before_restart = approvals
        .get_approval_reservation(&operation_id)
        .expect("approval lookup")
        .expect("approval tombstone");
    assert_eq!(
        committed_tombstone_before_restart.state(),
        ReplayReservationState::Committed
    );
    let expected_token_digest = token.token_digest().expect("legacy token digest");
    assert_eq!(committed_tombstone_before_restart.approval_set().members().len(), 1);
    assert_eq!(
        committed_tombstone_before_restart.approval_set().members()[0].token_id(),
        token.id.as_str()
    );
    assert_eq!(
        committed_tombstone_before_restart.approval_set().members()[0].token_digest(),
        expected_token_digest.as_str()
    );

    let restart_keypair = kernel.config.keypair.clone();
    let restart_policy_hash = kernel.config.policy_hash.clone();
    drop(kernel);
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut restart_config = make_config();
    restart_config.keypair = restart_keypair;
    restart_config.policy_hash = restart_policy_hash;
    let mut restarted = make_kernel(restart_config);
    restarted.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    restarted
        .set_admission_operation_store_handle(operations.clone())
        .expect("restarted operation store");
    restarted
        .set_approval_store_handle(approvals.clone())
        .expect("restarted approval store");
    restarted
        .set_budget_store_handle(budget)
        .expect("restarted budget store");

    let replay = restarted
        .evaluate_tool_call(&request)
        .await
        .expect_err("dispatch-committed legacy approval must not redispatch");
    assert!(replay.to_string().contains("already dispatch_committed"));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        operations
            .load(&operation_id)
            .expect("restarted operation load")
            .expect("restarted committed operation"),
        committed_before_restart
    );
    assert_eq!(
        approvals
            .get_approval_reservation(&operation_id)
            .expect("restarted approval lookup")
            .expect("restarted approval tombstone"),
        committed_tombstone_before_restart
    );
}

#[tokio::test]
async fn post_receipt_finalization_failure_retains_completed_operation() {
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    let mut kernel = make_kernel(config);
    let subject = Keypair::generate();
    let grant = make_governed_monetary_grant(
        "memory",
        "memory_write",
        100,
        1_000,
        "USD",
        50,
    );
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            make_scope(vec![grant]),
            3_600,
        )
        .expect("capability");
    let intent = make_governed_intent(
        "legacy-memory-intent",
        "memory",
        "memory_write",
        "store governed context",
        100,
        "USD",
    );
    let now = current_unix_timestamp();
    let request_id = "legacy-memory-finalization-failure";
    let request = ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "memory_write".to_string(),
        server_id: "memory".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({
            "collection": "governed-context",
            "id": "memory-1",
            "content": "persisted before provenance append",
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent.clone()),
        approval_token: Some(legacy_threshold_test_token(
            &kernel,
            &capability,
            &intent,
            request_id,
            "legacy-memory-token",
            now,
        )),
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "memory",
        vec!["memory_write"],
        invocations.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel.set_memory_provenance_store(std::sync::Arc::new(
        FailingThresholdMemoryProvenanceStore,
    ));

    let error = kernel
        .evaluate_tool_call(&request)
        .await
        .expect_err("post-receipt provenance failure must fail the response");
    assert!(error.to_string().contains("memory provenance append failed"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
    assert!(!operations
        .states()
        .contains(&AdmissionOperationState::OutcomeUnknownAfterDispatch));

    let receipt_log = kernel.receipt_log();
    let receipts = receipt_log.receipts();
    let receipt = receipts
        .last()
        .expect("allow receipt persisted before provenance failure");
    assert!(receipt.verify_signature().expect("receipt signature"));
    let projection = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/protocol_admission/admission_operation"))
        .expect("signed terminal operation projection");
    let operation_id = projection["operation_id"]
        .as_str()
        .expect("projected operation id");
    let operation = operations
        .load(operation_id)
        .expect("operation load")
        .expect("persisted operation");
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert_eq!(projection["state"], operation.state().as_str());
    assert_eq!(
        projection["dispatch_state"],
        operation.dispatch_state().as_str()
    );
    assert_eq!(projection["version"].as_u64(), Some(operation.version()));
}

#[tokio::test]
async fn top_level_threshold_payment_capture_ack_loss_retries_the_operation_binding() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let runtime = OperationAwareThresholdRuntimeHook::allowing();
    let payment = OperationAwareThresholdPaymentAdapter::with_capture_ack_loss();
    kernel.register_tool_server(Box::new(EchoServer::new("payments", vec!["transfer"])));
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget)
        .expect("budget store");
    kernel.set_runtime_admission_hook(std::sync::Arc::new(runtime.clone()));
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("operation-owned threshold response");

    assert_eq!(response.verdict, Verdict::Allow);
    let runtime_bindings = runtime.evaluations();
    assert_eq!(runtime_bindings.len(), 1);
    let payment_calls = payment.calls();
    assert_eq!(payment_calls.len(), 4);
    assert_eq!(payment_calls[0].0, "lookup_authorization");
    assert_eq!(payment_calls[1].0, "authorize");
    assert_eq!(payment_calls[2].0, "capture");
    assert_eq!(payment_calls[3].0, "capture");
    for payment_call in &payment_calls {
        assert_eq!(
            (&payment_call.1, &payment_call.2),
            (&runtime_bindings[0].0, &runtime_bindings[0].1)
        );
    }
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
}

#[tokio::test]
async fn top_level_threshold_runtime_denial_has_zero_durable_or_budget_mutation() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let runtime = OperationAwareThresholdRuntimeHook::denying();
    kernel.register_tool_server(Box::new(EchoServer::new("payments", vec!["transfer"])));
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel.set_runtime_admission_hook(std::sync::Arc::new(runtime.clone()));
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("threshold runtime denial response");

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
    assert_eq!(runtime.evaluations().len(), 1);
    assert!(runtime.releases().is_empty());
}

#[tokio::test]
async fn nested_threshold_dispatch_uses_the_same_durable_coordinator() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel.register_tool_server(Box::new(EchoServer::new("payments", vec!["transfer"])));
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![capability.clone()])
        .expect("session");
    kernel
        .activate_session(&session_id)
        .expect("active session");
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .expect("session request");
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
        .await
        .expect("nested threshold response");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionOperationState::PaymentAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
            AdmissionOperationState::DispatchCommitted,
            AdmissionOperationState::Completed,
        ]
    );
    assert_signed_receipt_matches_terminal_operation(
        &response,
        &operations,
        AdmissionOperationState::Completed,
    );
}

#[tokio::test]
async fn top_level_threshold_runtime_context_without_hook_denies_before_mutation() {
    let (mut kernel, capability, _grant, mut intent, mut request, now) = threshold_test_fixture();
    intent
        .as_tool_invocation_mut()
        .expect("threshold tool intent")
        .context = Some(serde_json::json!({
        "invoice_id": "inv-1001",
        "operator": "finance-ops",
        "chioAdmission": {
            "admissionId": "threshold-runtime-no-hook",
            "bundleSha256": "aa".repeat(32),
        },
    }));
    request.governed_intent = Some(intent.clone());
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);

    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("threshold runtime denial response");

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
    let metadata = response.receipt.metadata.expect("runtime denial metadata");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
}

#[tokio::test]
async fn nested_threshold_treaty_context_without_hook_denies_before_mutation() {
    let (mut kernel, capability, _grant, mut intent, mut request, now) = threshold_test_fixture();
    intent
        .as_tool_invocation_mut()
        .expect("threshold tool intent")
        .context = Some(serde_json::json!({
        "invoice_id": "inv-1001",
        "operator": "finance-ops",
        "chioTreaty": {
            "treatyScopeId": "threshold-treaty",
            "treatyScopeSha256": "bb".repeat(32),
            "ladderIntersectionId": "threshold-intersection",
            "ladderIntersectionSha256": "cc".repeat(32),
            "actionClassId": "payments.transfer",
        },
    }));
    request.governed_intent = Some(intent.clone());
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);

    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![capability.clone()])
        .expect("session");
    kernel
        .activate_session(&session_id)
        .expect("active session");
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .expect("session request");
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
        .await
        .expect("nested threshold treaty denial response");

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
    let metadata = response.receipt.metadata.expect("treaty denial metadata");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
}

#[tokio::test]
async fn top_level_threshold_incomplete_stream_records_unknown_outcome() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);

    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteStreamAfterSideEffectServer::new(
        "payments",
        vec!["transfer"],
        side_effects.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("threshold incomplete response");

    assert!(response.receipt.is_incomplete());
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
    assert_signed_receipt_matches_terminal_operation(
        &response,
        &operations,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
    );
    assert!(!operations
        .states()
        .contains(&AdmissionOperationState::Completed));
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("captured threshold usage")
            .invocation_count,
        1
    );
}
#[tokio::test]
async fn nested_threshold_incomplete_stream_records_unknown_outcome() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);

    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteStreamAfterSideEffectServer::new(
        "payments",
        vec!["transfer"],
        side_effects.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![capability.clone()])
        .expect("session");
    kernel
        .activate_session(&session_id)
        .expect("active session");
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .expect("session request");
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
        .await
        .expect("nested threshold incomplete response");

    assert!(response.receipt.is_incomplete());
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
    assert_signed_receipt_matches_terminal_operation(
        &response,
        &operations,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
    );
    assert!(!operations
        .states()
        .contains(&AdmissionOperationState::Completed));
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("captured threshold usage")
            .invocation_count,
        1
    );
}
