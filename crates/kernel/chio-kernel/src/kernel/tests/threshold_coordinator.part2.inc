#[tokio::test]
async fn top_level_threshold_enforces_aggregate_composite_quota() {
    let (mut kernel, capability, _grant, intent, mut first_request, now) = threshold_test_fixture();
    let capability = aggregate_limited_capability(&kernel, &capability, 1);
    first_request.capability = capability.clone();
    first_request.request_id = "threshold-aggregate-top-level-1".to_string();
    let mut second_request = first_request.clone();
    second_request.request_id = "threshold-aggregate-top-level-2".to_string();
    let authority = ThresholdArtifactAuthority::install(&mut kernel);
    authority.authorize_request(&capability, &intent, &mut first_request, now);
    authority.authorize_request(&capability, &intent, &mut second_request, now);

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
        .set_admission_operation_store_handle(operations)
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals)
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let first = kernel
        .evaluate_tool_call(&first_request)
        .await
        .expect("first threshold aggregate response");
    assert_eq!(first.verdict, Verdict::Allow);
    let denied = kernel
        .evaluate_tool_call_with_unchecked_receipt_metadata_for_test(
            &second_request,
            Some(serde_json::json!({
                "financial": {
                    "budget_remaining": 413_729,
                    "budget_total": 937_000,
                    "attempted_cost": 17,
                    "currency": "SECRET"
                },
                "governed_transaction": {
                    "economic_authorization": "FORGED-ECONOMIC-AUTHORIZATION"
                }
            })),
        )
        .await
        .expect("second top-level threshold aggregate denial response");
    assert_opaque_budget_authorization_denial(&denied);
    assert!(!serde_json::to_string(&denied.receipt.metadata)
        .expect("threshold denial metadata")
        .contains("FORGED-ECONOMIC-AUTHORIZATION"));
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "the aggregate ceiling must cover distinct threshold approval sets"
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1
    );
}

#[tokio::test]
async fn nested_threshold_enforces_aggregate_composite_quota() {
    let (mut kernel, capability, _grant, intent, mut first_request, now) = threshold_test_fixture();
    let capability = aggregate_limited_capability(&kernel, &capability, 1);
    first_request.capability = capability.clone();
    first_request.request_id = "threshold-aggregate-nested-1".to_string();
    let mut second_request = first_request.clone();
    second_request.request_id = "threshold-aggregate-nested-2".to_string();
    let authority = ThresholdArtifactAuthority::install(&mut kernel);
    authority.authorize_request(&capability, &intent, &mut first_request, now);
    authority.authorize_request(&capability, &intent, &mut second_request, now);

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
        .set_admission_operation_store_handle(operations)
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals)
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let session_id = kernel
        .open_session(first_request.agent_id.clone(), vec![capability.clone()])
        .expect("session");
    kernel
        .activate_session(&session_id)
        .expect("active session");
    let mut client = NoopNestedFlowClient;

    let first_context = make_operation_context(
        &session_id,
        &first_request.request_id,
        &first_request.agent_id,
    );
    kernel
        .begin_session_request(&first_context, OperationKind::ToolCall, true)
        .expect("first session request");
    let first = kernel
        .evaluate_tool_call_with_nested_flow_client_async(
            &first_context,
            &first_request,
            &mut client,
            None,
        )
        .await
        .expect("first nested threshold aggregate response");
    assert_eq!(first.verdict, Verdict::Allow);

    let second_context = make_operation_context(
        &session_id,
        &second_request.request_id,
        &second_request.agent_id,
    );
    kernel
        .begin_session_request(&second_context, OperationKind::ToolCall, true)
        .expect("second session request");
    let denied = kernel
        .evaluate_tool_call_with_nested_flow_client_async(
            &second_context,
            &second_request,
            &mut client,
            None,
        )
        .await
        .expect("second nested threshold aggregate denial response");
    assert_opaque_budget_authorization_denial(&denied);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "nested threshold dispatch must share the aggregate ceiling"
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1
    );
}

#[tokio::test]
async fn top_level_threshold_does_not_bypass_supplemental_broker_admission() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.supplemental_authorization = Some(
        chio_core::OpaqueSupplementalAuthorization::new(
            "broker:threshold-unconfigured",
            vec![0x43, 0x48, 0x49, 0x4f],
        )
        .expect("supplemental authorization"),
    );
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
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
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    match kernel.evaluate_tool_call(&request).await {
        Ok(response) => assert_eq!(
            response.verdict,
            Verdict::Deny,
            "threshold dispatch ignored an unconfigured supplemental authorization"
        ),
        Err(error) => assert!(
            error.to_string().contains("supplemental"),
            "unexpected supplemental denial: {error}"
        ),
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(
        operations.states().is_empty(),
        "supplemental preverification must precede durable admission mutation"
    );
    assert!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .is_none(),
        "supplemental preverification must precede budget mutation"
    );
}

#[tokio::test]
async fn threshold_security_pre_dispatch_denial_reverses_the_composite_hold() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    let budget = durable_atomic_test_budget_store("threshold-security-pre-dispatch-payment");
    let runtime = OperationAwareThresholdRuntimeHook::allowing();
    let payment = OperationAwareThresholdPaymentAdapter::with_release_ack_loss();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let hook_calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(
        hook_calls.clone(),
        Some("injected threshold security denial"),
    );
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals)
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel.set_runtime_admission_hook(std::sync::Arc::new(runtime.clone()));
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(capture.hook);
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, "threshold-security-deny", 21),
        )
        .await
        .expect("threshold security denial response");

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionOperationState::PaymentAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CompensationPending,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ],
        "a security denial must terminalize the threshold saga before capture"
    );
    let usage = budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("reversed budget usage");
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.total_cost_exposed, 0);
    let runtime_bindings = runtime.evaluations();
    assert_eq!(runtime_bindings.len(), 1);
    assert!(runtime.releases().is_empty());
    let payment_calls = payment.calls();
    assert_eq!(payment_calls.len(), 4);
    assert_eq!(payment_calls[0].0, "lookup_authorization");
    assert_eq!(payment_calls[1].0, "authorize");
    assert_eq!(payment_calls[2].0, "release");
    assert_eq!(payment_calls[3].0, "release");
    assert_eq!(
        (&payment_calls[1].1, &payment_calls[1].2),
        (&payment_calls[2].1, &payment_calls[2].2)
    );
    assert_eq!(
        (&payment_calls[1].1, &payment_calls[1].2),
        (&payment_calls[3].1, &payment_calls[3].2)
    );
}

#[tokio::test]
async fn threshold_missing_tool_route_denies_before_admission_mutation() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
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
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("missing route denial response");

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        operations.states().is_empty(),
        "route preflight must deny before durable threshold admission mutation"
    );
    assert!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .is_none(),
        "route preflight must deny before budget mutation"
    );
}

#[tokio::test]
async fn top_level_threshold_connector_error_retains_operation_owned_budget() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
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
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("terminal deny response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let usage = budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("budget usage");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
}

#[tokio::test]
async fn nested_threshold_connector_error_retains_operation_owned_budget() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
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
        .expect("terminal deny response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let usage = budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("budget usage");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
}

#[tokio::test]
async fn threshold_nonce_preflight_mutates_no_authority_before_presented_nonce() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let denied_artifact = std::sync::Arc::new(std::sync::Mutex::new(None));
    kernel
        .set_authority_artifact_trust_resolver(std::sync::Arc::new(
            SelectiveAuthorityArtifactTrustResolver {
                key: kernel.public_key(),
                denied_artifact: std::sync::Arc::clone(&denied_artifact),
            },
        ))
        .expect("nonce artifact resolver");
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let nonces = Box::new(DurableThresholdNonceStore::new());
    kernel.register_tool_server(Box::new(EchoServer::new("payments", vec!["transfer"])));
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals.clone())
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    let nonce_config = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel
        .set_execution_nonce_store(nonce_config, nonces)
        .expect("nonce store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let preflight = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("nonce preflight response");
    assert_eq!(preflight.verdict, Verdict::Allow);
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
    let nonce = preflight.execution_nonce.expect("minted nonce");
    request.execution_nonce = Some(*nonce);

    *denied_artifact.lock().expect("denied nonce artifact") = Some(
        crate::execution_nonce::execution_nonce_signed_artifact(
            request.execution_nonce.as_ref().expect("presented nonce"),
        )
        .expect("canonical nonce artifact"),
    );
    let denied = kernel.evaluate_tool_call(&request).await;
    assert!(denied.is_err());
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());

    *denied_artifact.lock().expect("denied nonce artifact") = None;

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("nonce-authorized threshold response");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
}

#[test]
fn threshold_coordinator_orders_participants_and_commits_before_dispatch() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
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
    let coordinator_authority_id = format!("kernel:{}", kernel.public_key().to_hex());
    let prepared = prepared_threshold_coordinator_admission_for_authority(
        &coordinator_authority_id,
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let (permit, _budget_mutation) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("dispatch permit");
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
        ]
    );
    assert_eq!(
        approvals
            .get_approval_reservation(permit.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1
    );
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::DispatchCommitted)
    );
}

#[test]
fn threshold_coordinator_accepts_operation_owned_runtime_and_payment_participants() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = durable_atomic_test_budget_store("threshold-operation-payment-participants");
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    let prepared = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let operation_id = prepared.operation().operation_id().to_string();
    let request_binding_hash = prepared.operation().request_binding_hash().to_string();
    let runtime = OperationAwareThresholdRuntimeHook::allowing();
    let payment = OperationAwareThresholdPaymentAdapter::new();
    kernel.set_runtime_admission_hook(std::sync::Arc::new(runtime.clone()));
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");

    let (permit, _) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("operation-owned threshold participants");

    assert_eq!(permit.operation_id(), operation_id);
    assert_eq!(
        runtime.evaluations(),
        vec![(operation_id.clone(), request_binding_hash.clone())]
    );
    assert_eq!(
        payment.calls(),
        vec![
            (
                "lookup_authorization".to_string(),
                operation_id.clone(),
                request_binding_hash.clone(),
            ),
            ("authorize".to_string(), operation_id, request_binding_hash,),
        ]
    );
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
        ]
    );
}

#[test]
fn threshold_pure_runtime_denial_has_no_reservation_or_durable_mutation() {
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
    let prepared = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let operation_id = prepared.operation().operation_id().to_string();
    let request_binding_hash = prepared.operation().request_binding_hash().to_string();
    let runtime = OperationAwareThresholdRuntimeHook::denying();
    kernel.set_runtime_admission_hook(std::sync::Arc::new(runtime.clone()));

    let error = match kernel.coordinate_threshold_tool_admission(
        &request,
        &capability,
        0,
        &grant,
        prepared,
    ) {
        Ok(_) => panic!("runtime denial must fail before durable mutation"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("runtime denial"));
    assert_eq!(
        runtime.evaluations(),
        vec![(operation_id, request_binding_hash)]
    );
    assert!(runtime.releases().is_empty());
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
}

#[test]
fn threshold_rejects_mutating_runtime_hook_before_prepared_is_persisted() {
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
    let prepared = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let runtime = ReservingThresholdRuntimeHook::default();
    kernel.set_runtime_admission_hook(std::sync::Arc::new(runtime.clone()));

    let error = match kernel.coordinate_threshold_tool_admission(
        &request,
        &capability,
        0,
        &grant,
        prepared,
    ) {
        Ok(_) => panic!("mutating runtime hook must fail before durable mutation"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("pure pre-persist evaluation"));
    assert_eq!(runtime.evaluations(), 0);
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
}

#[test]
fn threshold_rejects_legacy_non_idempotent_payment_without_calling_authorize() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = durable_atomic_test_budget_store("threshold-legacy-payment-adapter-rejection");
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
    let payment = LegacyThresholdPaymentAdapter::default();
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");

    let error = match kernel.coordinate_threshold_tool_admission(
        &request,
        &capability,
        0,
        &grant,
        prepared,
    ) {
        Ok(_) => panic!("legacy payment adapter must fail closed"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("requires authoritative authorization lookup and operation-bound payment mutations"));
    assert_eq!(payment.authorizations(), 0);
    assert!(operations.states().is_empty());
    assert!(budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .is_none());
}

#[test]
fn threshold_payment_authorization_ack_loss_recovers_by_operation_lookup() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "threshold-payment-authorization-ack-loss",
        ))
        .expect("budget store");
    let prepared = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let operation_id = prepared.operation().operation_id().to_string();
    let request_binding_hash = prepared.operation().request_binding_hash().to_string();
    let payment = OperationAwareThresholdPaymentAdapter::with_authorize_ack_loss();
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");

    let (permit, _) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("payment authorization acknowledgement recovery");

    assert_eq!(
        permit.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        payment.calls(),
        vec![
            (
                "lookup_authorization".to_string(),
                operation_id.clone(),
                request_binding_hash.clone(),
            ),
            (
                "authorize".to_string(),
                operation_id.clone(),
                request_binding_hash.clone(),
            ),
            (
                "lookup_authorization".to_string(),
                operation_id,
                request_binding_hash,
            ),
        ]
    );
    assert_eq!(payment.authorization_mutations(), 1);
    assert_eq!(
        operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::PaymentAuthorized)
            .count(),
        1
    );
}

#[test]
fn threshold_no_ceiling_mustprepay_ack_loss_recovers_by_operation_lookup() {
    let (mut kernel, capability, mut grant, _intent, mut request, _now) =
        threshold_test_fixture();
    grant.max_cost_per_invocation = None;
    grant.max_total_cost = None;
    request.governed_intent = Some(make_mustprepay_intent(
        "threshold-no-ceiling-prepay",
        "payments",
        "transfer",
        100,
        "USD",
    ));
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "threshold-no-ceiling-payment-ack-loss",
        ))
        .expect("budget store");
    let prepared = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let operation_id = prepared.operation().operation_id().to_string();
    let request_binding_hash = prepared.operation().request_binding_hash().to_string();
    let payment = OperationAwareThresholdPaymentAdapter::with_authorize_ack_loss();
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");

    let (permit, mutation) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("no-ceiling prepayment authorization acknowledgement recovery");

    assert!(mutation.charge_result().is_none());
    assert!(mutation.admission_operation_binding().is_some());
    assert!(permit.payment_authorization().is_some());
    assert_eq!(
        payment.calls(),
        vec![
            (
                "lookup_authorization".to_string(),
                operation_id.clone(),
                request_binding_hash.clone(),
            ),
            (
                "authorize".to_string(),
                operation_id.clone(),
                request_binding_hash.clone(),
            ),
            (
                "lookup_authorization".to_string(),
                operation_id,
                request_binding_hash,
            ),
        ]
    );
    assert_eq!(payment.authorization_mutations(), 1);
}

#[test]
fn threshold_settled_mustprepay_refunds_captured_transaction_and_quote() {
    let (mut kernel, _capability, _grant, _intent, mut request, _now) = threshold_test_fixture();
    request.governed_intent = Some(make_mustprepay_intent(
        "threshold-settled-refund",
        "payments",
        "transfer",
        100,
        "USD",
    ));
    let payment = OperationAwareThresholdPaymentAdapter::new();
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");
    let binding = BudgetAdmissionOperationBinding::new(
        "threshold-refund-operation".to_string(),
        "ab".repeat(32),
    )
    .expect("valid refund operation binding");
    let mut charge = make_provisional_charge(10, "EUR");
    charge.admission_operation = Some(binding.clone());
    let mutation = PreExecutionBudgetMutation::Charge(Box::new(charge));
    let authorization = PaymentAuthorization {
        authorization_id: "authorization-hold-reference".to_string(),
        settled: true,
        metadata: serde_json::json!({
            "transaction_id": "captured-transaction-reference"
        }),
    };

    kernel
        .release_threshold_payment_authorization(&request, &mutation, &authorization)
        .expect("refund settled threshold prepayment");

    assert_eq!(
        payment.refunds(),
        vec![(
            "captured-transaction-reference".to_string(),
            100,
            "USD".to_string(),
        )],
        "refund must name the captured transaction and use the prepaid quote"
    );
    assert_eq!(
        payment.calls(),
        vec![(
            "refund".to_string(),
            binding.operation_id().to_string(),
            binding.request_binding_hash().to_string(),
        )]
    );
}

#[test]
fn threshold_delegated_budget_is_operation_owned_exact_retry_and_oversubscription_safe() {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp: _,
        child_b_kp: _,
        path,
    } = make_sibling_sum_monetary_fixture("threshold-operation-owned-delegation");
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations)
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");

    let request_a = make_request("threshold-delegated-a", &child_a, "compute", "cost-srv");
    let prepared_a = prepared_threshold_coordinator_admission(
        &request_a.request_id,
        &child_a.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let grant_a = child_a.scope.grants[0].clone();
    let (permit_a, _) = kernel
        .coordinate_threshold_tool_admission(&request_a, &child_a, 0, &grant_a, prepared_a)
        .expect("first delegated threshold admission");

    assert!(kernel
        .reserve_threshold_delegated_budget(&child_a, permit_a.operation())
        .expect("exact delegated retry"));

    let request_b = make_request("threshold-delegated-b", &child_b, "compute", "cost-srv");
    let prepared_b = prepared_threshold_coordinator_admission(
        &request_b.request_id,
        &child_b.id,
        "77",
        "88",
        &[("approval-c", "99"), ("approval-d", "aa")],
    );
    let grant_b = child_b.scope.grants[0].clone();
    let error = match kernel
        .coordinate_threshold_tool_admission(&request_b, &child_b, 0, &grant_b, prepared_b)
    {
        Ok(_) => panic!("oversubscribing delegated threshold request must deny"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("sibling"));

    kernel
        .release_threshold_delegated_budget(&child_a, permit_a.operation())
        .expect("release operation-owned delegated lease");
    let request_b_retry = make_request(
        "threshold-delegated-b-retry",
        &child_b,
        "compute",
        "cost-srv",
    );
    let prepared_b_retry = prepared_threshold_coordinator_admission(
        &request_b_retry.request_id,
        &child_b.id,
        "99",
        "aa",
        &[("approval-e", "bb"), ("approval-f", "cc")],
    );
    let (permit_b, _) = kernel
        .coordinate_threshold_tool_admission(
            &request_b_retry,
            &child_b,
            0,
            &grant_b,
            prepared_b_retry,
        )
        .expect("delegated threshold admission after exact release");
    assert_eq!(
        permit_b.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );

    drop(kernel);
    let _ = std::fs::remove_file(path);
}

#[test]
fn threshold_coordinator_denies_overlapping_member_reuse_and_compensates() {
    let (mut kernel, capability, grant, _intent, mut request, _now) = threshold_test_fixture();
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

    let first = prepared_threshold_coordinator_admission(
        "threshold-request-a",
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    request.request_id = "threshold-request-a".to_string();
    let _ = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, first)
        .expect("first dispatch permit");

    let coordinator_authority_id = format!("kernel:{}", kernel.public_key().to_hex());
    let second = prepared_threshold_coordinator_admission_for_authority(
        &coordinator_authority_id,
        "threshold-request-c",
        &capability.id,
        "77",
        "88",
        &[("approval-a", "55"), ("approval-c", "99")],
    );
    request.request_id = "threshold-request-c".to_string();
    let error = match kernel.coordinate_threshold_tool_admission(
        &request,
        &capability,
        0,
        &grant,
        second,
    ) {
        Ok(_) => panic!("overlapping member reuse must deny"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("approval reservation"));
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1
    );
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
}

#[test]
fn threshold_coordinator_rejects_distinct_operations_aliasing_one_budget_hold() {
    let (mut kernel, capability, mut grant, _intent, request, _now) = threshold_test_fixture();
    grant.max_invocations = Some(1);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    kernel
        .set_admission_operation_store_handle(operations)
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals)
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");

    let first = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );
    let _ = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, first)
        .expect("first dispatch permit");

    let second = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "77",
        "88",
        &[("approval-c", "99"), ("approval-d", "aa")],
    );
    let error = match kernel.coordinate_threshold_tool_admission(
        &request,
        &capability,
        0,
        &grant,
        second,
    ) {
        Ok(_) => panic!("a distinct operation must not adopt an existing budget hold"),
        Err(error) => error,
    };

    let denial = error.to_string();
    assert!(
        denial.contains("reused for a different composite mutation")
            || denial.contains("belongs to a different admission operation")
            || denial.contains("belongs to a different admission request_binding_hash"),
        "unexpected ownership denial: {denial}"
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("captured threshold usage")
            .invocation_count,
        1
    );
}

#[test]
fn threshold_coordinator_terminalizes_definitive_budget_denial() {
    let (mut kernel, capability, mut grant, _intent, request, _now) = threshold_test_fixture();
    grant.max_invocations = Some(0);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals.clone())
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
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
    let operation_id = prepared.operation().operation_id().to_string();
    let approval_set = prepared.approval_set().clone();

    let error = match kernel.coordinate_threshold_tool_admission(
        &request,
        &capability,
        0,
        &grant,
        prepared,
    ) {
        Ok(_) => panic!("exhausted budget must deny"),
        Err(error) => error,
    };
    assert!(matches!(error, KernelError::BudgetExhausted(_)));
    assert_eq!(
        operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::CompensationPending,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ]
    );
    let tombstone = approvals
        .get_approval_reservation(&operation_id)
        .expect("approval lookup")
        .expect("cleanup cancellation tombstone");
    assert_eq!(tombstone.state(), ReplayReservationState::Cancelled);
    assert_eq!(
        approvals
            .reserve_approval_set(&operation_id, &approval_set)
            .expect("late exact approval reserve"),
        tombstone
    );
}

#[test]
fn threshold_coordinator_recovers_participant_acknowledgement_loss() {
    let (mut kernel, capability, grant, _intent, request, _now) = threshold_test_fixture();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::with_ack_loss(
        AdmissionOperationState::BudgetAuthorized,
    ));
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::with_ack_loss());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::with_capture_ack_loss());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals.clone())
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    let prepared = prepared_threshold_coordinator_admission(
        &request.request_id,
        &capability.id,
        "22",
        "44",
        &[("approval-a", "55"), ("approval-b", "66")],
    );

    let (permit, _mutation) = kernel
        .coordinate_threshold_tool_admission(&request, &capability, 0, &grant, prepared)
        .expect("acknowledgement loss recovery");
    assert_eq!(
        permit.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        approvals
            .get_approval_reservation(permit.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1
    );
}

#[tokio::test]
async fn ordinary_composite_recovers_budget_authorized_transition_ack_loss() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(2);
    let ordinary = make_capability(&kernel, &subject, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &ordinary, 2);
    let request = make_request(
        "ordinary-composite-budget-authorized-ack-loss",
        &capability,
        "read_file",
        "srv-a",
    );
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::with_ack_loss(
        AdmissionOperationState::BudgetAuthorized,
    ));
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");

    let first = kernel.evaluate_tool_call(&request).await;
    let eventual = match first {
        Ok(response) if response.verdict == Verdict::Allow => response,
        Ok(response) => {
            assert_eq!(
                invocations.load(Ordering::SeqCst),
                0,
                "a denied first attempt must not enter the tool server"
            );
            kernel
                .evaluate_tool_call(&request)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "ordinary composite admission did not recover after {response:?}: {error}"
                    )
                })
        }
        Err(_) => kernel
            .evaluate_tool_call(&request)
            .await
            .expect("retry must resume the persisted budget-authorized operation"),
    };

    assert_eq!(
        eventual.verdict,
        Verdict::Allow,
        "ordinary composite recovery response: {eventual:?}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "acknowledgement recovery must issue at most one tool dispatch"
    );
    assert_eq!(
        operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::BudgetAuthorized)
            .count(),
        1,
        "the persisted composite hold must be reused"
    );
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1
    );
}

#[tokio::test]
async fn concurrent_ordinary_aggregate_admission_emits_one_outbound_effect() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.policy_hash = "37".repeat(32);
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let ordinary = make_capability(&kernel, &subject, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &ordinary, 1);
    let request = make_request(
        "ordinary-composite-concurrent-one-effect",
        &capability,
        "read_file",
        "srv-a",
    );
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");

    let (first, second) = tokio::join!(
        kernel.evaluate_tool_call(&request),
        kernel.evaluate_tool_call(&request)
    );
    let allowed = [first, second]
        .into_iter()
        .filter(|result| {
            result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Allow)
        })
        .count();
    assert_eq!(
        allowed, 1,
        "exactly one coordinator may return dispatch success"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "the shared dispatch CAS must permit one outbound effect"
    );
    assert_eq!(
        operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::DispatchCommitted)
            .count(),
        1
    );
}

#[tokio::test]
async fn single_node_invalid_returned_authority_reverses_with_trusted_request_authority() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.policy_hash = "34".repeat(32);
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let ordinary = make_capability(&kernel, &subject, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &ordinary, 1);
    let request = make_request(
        "ordinary-composite-forged-authority",
        &capability,
        "read_file",
        "srv-a",
    );
    let trusted_authority = kernel.local_budget_event_authority();
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget =
        std::sync::Arc::new(DurableThresholdBudgetStore::with_forged_authorize_authority());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("invalid returned authority deny response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("configured hard budget ceiling")));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(budget.reverse_authorities(), vec![Some(trusted_authority)]);
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        0,
        "trusted-authority cleanup must reverse the reserved invocation"
    );
}

#[tokio::test]
async fn invalid_capture_metadata_retains_capture_pending_and_never_dispatches_or_reverses() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.policy_hash = "35".repeat(32);
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let ordinary = make_capability(&kernel, &subject, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &ordinary, 1);
    let request = make_request(
        "ordinary-composite-invalid-capture-metadata",
        &capability,
        "read_file",
        "srv-a",
    );
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::with_invalid_capture_metadata());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");

    for attempt in 1..=2 {
        let response = kernel
            .evaluate_tool_call(&request)
            .await
            .unwrap_or_else(|error| panic!("capture recovery attempt {attempt} failed: {error}"));
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.reason.as_deref().is_some_and(
            |reason| reason.contains("budget capture requires exact authority recovery")
        ));
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::CapturePending),
        "invalid committed capture evidence must stay recoverable"
    );
    assert!(
        budget.reverse_authorities().is_empty(),
        "captured quota must never be reversed"
    );
    assert_eq!(
        budget
            .get_usage(&capability.id, 0)
            .expect("budget lookup")
            .expect("budget usage")
            .invocation_count,
        1,
        "exact retry must re-query the one captured invocation"
    );
}

#[tokio::test]
async fn ha_budget_accepts_remote_assigned_authority_for_capture_and_reverse() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.policy_hash = "36".repeat(32);
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(2);
    let ordinary = make_capability(&kernel, &subject, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &ordinary, 2);
    let first_request = make_request(
        "ordinary-ha-remote-authority-capture",
        &capability,
        "read_file",
        "srv-a",
    );
    let second_request = make_request(
        "ordinary-ha-remote-authority-reverse",
        &capability,
        "read_file",
        "srv-a",
    );
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::shared());
    kernel
        .set_admission_operation_store_handle(operations)
        .expect("operation store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("shared budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");

    let first = kernel
        .evaluate_tool_call(&first_request)
        .await
        .expect("remote-assigned capture response");
    assert_eq!(first.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let hook_calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture =
        security_pre_dispatch_capture(hook_calls.clone(), Some("injected HA pre-dispatch denial"));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(capture.hook);
    let second = kernel
        .evaluate_tool_call_with_security_context(
            &second_request,
            &security_pre_dispatch_context_for(&second_request, "ordinary-ha-reverse", 37),
        )
        .await
        .expect("remote-assigned reverse response");
    assert_eq!(second.verdict, Verdict::Deny);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        budget.reverse_authorities(),
        vec![
            Some(DurableThresholdBudgetStore::remote_authority()),
            Some(DurableThresholdBudgetStore::remote_authority()),
        ],
        "HA direct reversal and durable cleanup replay must reuse the exact authority lease assigned at authorization"
    );
}
