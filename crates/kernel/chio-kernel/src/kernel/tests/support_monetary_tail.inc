#[test]
fn plain_limited_grants_are_operation_owned_and_exact_retries_never_redispatch() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let operations =
        durable_test_admission_operation_store("plain-limited-operation-owned-operations");
    let budget = durable_atomic_test_budget_store("plain-limited-operation-owned-budget");
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("plain limited admission operation store");
    kernel
        .set_budget_store_handle(budget)
        .expect("plain limited budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("plain limited payment authority");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));
    assert!(kernel.partition_escrow_registry.is_none());
    assert!(!kernel.threshold_governed_approvals_enabled);

    let agent = Keypair::generate();
    let monetary_capability = kernel
        .issue_capability(
            &agent.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1_000, "USD",
            )]),
            3_600,
        )
        .expect("plain monetary capability");
    let monetary_request = make_request(
        "plain-monetary-operation-owned-retry",
        &monetary_capability,
        "compute",
        "cost-srv",
    );

    let invocation_grant = make_invocation_limited_grant("cost-srv", "compute", 1);
    assert!(invocation_grant.max_cost_per_invocation.is_none());
    assert!(invocation_grant.max_total_cost.is_none());
    let invocation_capability = kernel
        .issue_capability(
            &agent.public_key(),
            make_scope(vec![invocation_grant]),
            3_600,
        )
        .expect("plain invocation-limited capability");
    let invocation_request = make_request(
        "plain-invocation-limited-operation-owned-retry",
        &invocation_capability,
        "compute",
        "cost-srv",
    );

    for (capability, request) in [
        (&monetary_capability, &monetary_request),
        (&invocation_capability, &invocation_request),
    ] {
        assert!(capability.aggregate_invocation_budget.is_none());
        assert!(request.supplemental_authorization.is_none());
        assert!(request.threshold_approval_proposal.is_none());
        assert!(request.approval_token.is_none());
        assert!(request.approval_tokens.is_empty());
    }

    let assert_exact_retry = |request: &ToolCallRequest, expected_invocations: usize| {
        let first = kernel
            .evaluate_tool_call_blocking(request)
            .expect("first plain limited response");
        assert_eq!(first.verdict, Verdict::Allow);
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            expected_invocations
        );
        assert!(first
            .receipt
            .verify_signature()
            .expect("plain limited receipt signature"));
        let operation_projection = first
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/protocol_admission/admission_operation"))
            .expect("plain limited receipt must carry its admission operation");
        let operation_id = operation_projection["operation_id"]
            .as_str()
            .expect("plain limited operation id");
        let operation = operations
            .load(operation_id)
            .expect("plain limited operation lookup")
            .expect("plain limited operation");
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert_eq!(
            operation.dispatch_state(),
            AdmissionDispatchState::EffectCompleted
        );
        assert_eq!(operation_projection["state"], operation.state().as_str());
        assert_eq!(
            operation_projection["dispatch_state"],
            operation.dispatch_state().as_str()
        );

        let retry = kernel
            .evaluate_tool_call_blocking(request)
            .expect("exact plain limited retry must return a signed denial");
        assert_eq!(retry.verdict, Verdict::Deny);
        assert!(retry
            .receipt
            .verify_signature()
            .expect("plain limited retry receipt signature"));
        assert!(retry.reason.as_deref().is_some_and(|reason| {
            reason.contains("cannot replay authorization from completed")
        }));
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            expected_invocations,
            "an exact retry of a completed plain limited operation must not redispatch"
        );
    };

    assert_exact_retry(&monetary_request, 1);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an exact retry must not authorize payment twice"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an exact retry must not capture payment twice"
    );

    assert_exact_retry(&invocation_request, 2);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an invocation-only grant must not create a rail authorization"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an invocation-only grant must not create a rail capture"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an invocation-only grant must not create a rail release"
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an invocation-only grant must not create a rail refund"
    );
}

#[test]
fn no_ceiling_mustprepay_exact_retry_never_redispatches_or_prepays_twice() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let operations =
        durable_test_admission_operation_store("no-ceiling-mustprepay-retry-operations");
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("no-ceiling MustPrepay admission operation store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "no-ceiling-mustprepay-retry-budget",
        ))
        .expect("no-ceiling MustPrepay budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("no-ceiling MustPrepay payment authority");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3_600,
        )
        .expect("no-ceiling MustPrepay capability");
    let intent = make_mustprepay_intent(
        "intent-no-ceiling-operation-retry",
        "cost-srv",
        "compute",
        100,
        "USD",
    );
    let request = mustprepay_tool_call(
        "request-no-ceiling-operation-retry",
        &capability,
        &agent,
        intent,
        &kernel,
    );

    let first = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("first no-ceiling MustPrepay response");
    assert_eq!(first.verdict, Verdict::Allow);
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let operation_id = first
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.pointer("/protocol_admission/admission_operation/operation_id")
        })
        .and_then(serde_json::Value::as_str)
        .expect("no-ceiling MustPrepay receipt operation id");
    let operation = operations
        .load(operation_id)
        .expect("no-ceiling MustPrepay operation lookup")
        .expect("no-ceiling MustPrepay operation");
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::EffectCompleted
    );

    let retry = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("exact no-ceiling MustPrepay retry response");
    assert_eq!(retry.verdict, Verdict::Deny);
    assert!(retry
        .reason
        .as_deref()
        .is_some_and(|reason| { reason.contains("cannot replay authorization from completed") }));
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an exact no-ceiling MustPrepay retry must not redispatch"
    );
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an exact no-ceiling MustPrepay retry must not reauthorize payment"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an exact no-ceiling MustPrepay retry must not capture payment twice"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_async_evaluate_after_monetary_admission_unwinds_budget_payment_and_receipt() {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(
            "drop-after-admission-operations",
        ))
        .expect("drop admission operation store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "drop-after-admission-budget",
        ))
        .expect("drop budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("install payment adapter");
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
    }));

    struct AbortEvidenceGuard;
    impl Guard for AbortEvidenceGuard {
        fn name(&self) -> &str {
            "abort-evidence"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow_with_evidence(vec![GuardEvidence {
                guard_name: "abort-evidence".to_string(),
                verdict: true,
                details: Some("pre-invocation evidence recorded before abort".to_string()),
            }]))
        }
    }
    kernel.add_guard(Box::new(AbortEvidenceGuard));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-drop-after-admission".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("pending monetary tool should be invoked before abort");
    eval.abort();
    let join = eval
        .await
        .expect_err("aborted evaluation should not complete");
    assert!(join.is_cancelled());

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_cancelled());
    assert_eq!(receipt.evidence.len(), 1);
    assert_eq!(receipt.evidence[0].guard_name, "abort-evidence");
    let terminal = &receipt.metadata.as_ref().unwrap()["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
}

#[derive(Clone, Copy)]
enum DropCleanupFailureSource {
    Payment,
    BudgetStore,
}

async fn assert_post_dispatch_drop_cleanup_fault(source: DropCleanupFailureSource) {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(
            "post-dispatch-drop-cleanup-operations",
        ))
        .expect("post-dispatch cleanup admission operation store");
    match source {
        DropCleanupFailureSource::Payment => {
            kernel
                .set_budget_store_handle(durable_atomic_test_budget_store(
                    "post-dispatch-drop-payment-cleanup-budget",
                ))
                .expect("post-dispatch payment cleanup budget store");
            kernel
                .set_payment_adapter(Box::new(FailingReleasePaymentAdapter))
                .expect("install payment adapter");
        }
        DropCleanupFailureSource::BudgetStore => {
            kernel
                .set_budget_store_handle(std::sync::Arc::new(FailingReleaseBudgetStore::new()))
                .expect("budget store");
        }
    }
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = make_request(
        "req-post-dispatch-drop-cleanup-fault",
        &cap,
        "compute",
        "cost-srv",
    );

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("pending monetary tool should be entered before abort");
    eval.abort();
    assert!(eval.await.unwrap_err().is_cancelled());

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_cancelled());
    let metadata = receipt.metadata.as_ref().unwrap();
    assert!(metadata["budget_authority"]["terminal"].is_null());
    let financial_budget_authority = receipt
        .financial_budget_authority_metadata()
        .expect("cleanup fault receipt must retain typed budget authorization metadata");
    assert!(financial_budget_authority.terminal.is_none());
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_cleanup_failed"],
        true
    );
    let fault = &metadata["chio_runtime"]["post_dispatch_cleanup_faults"][0];
    let expected_step = match source {
        DropCleanupFailureSource::Payment => "payment_release",
        DropCleanupFailureSource::BudgetStore => "budget_hold_release",
    };
    assert_eq!(fault["step"], expected_step);
    let reason = fault["reason"].as_str().unwrap();
    assert!(reason.contains("[REDACTED-API-KEY]"));
    assert!(!reason.contains("sk_live_"));
    assert!(fault["attempted_release_event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
    let hold_ids = fault["hold_ids"].as_array().unwrap();
    assert!(hold_ids.iter().any(|id| id == &cap.id));
    let budget_hold_id = metadata["budget_authority"]["hold_id"].as_str().unwrap();
    assert!(hold_ids.iter().any(|id| id == budget_hold_id));
    if matches!(source, DropCleanupFailureSource::Payment) {
        let payment_hold_id = FailingReleasePaymentAdapter::operation_authorization_id(
            "req-post-dispatch-drop-cleanup-fault",
            100,
            "USD",
        );
        assert!(hold_ids.iter().any(|id| id == &payment_hold_id));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_dispatch_drop_payment_cleanup_failure_is_signed() {
    assert_post_dispatch_drop_cleanup_fault(DropCleanupFailureSource::Payment).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_dispatch_drop_budget_cleanup_failure_is_signed() {
    assert_post_dispatch_drop_cleanup_fault(DropCleanupFailureSource::BudgetStore).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_dispatch_drop_cleanup_failure_rejects_forged_budget_authority() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(
            "forged-budget-metadata-operations",
        ))
        .expect("forged metadata admission operation store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "forged-budget-metadata-budget",
        ))
        .expect("forged metadata budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("forged metadata payment authority");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1_000, "USD",
            )]),
            3_600,
        )
        .expect("forged metadata capability");
    let request = make_request(
        "req-forged-budget-authority-metadata",
        &capability,
        "compute",
        "cost-srv",
    );

    let error = kernel
        .evaluate_tool_call_with_metadata(&request, Some(forged_budget_authority_metadata()))
        .await
        .expect_err("caller budget authority metadata must be rejected");
    assert!(matches!(error, KernelError::InvalidReceiptMetadata(_)));
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "reserved caller metadata must be rejected before dispatch"
    );
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "reserved caller metadata must be rejected before rail authorization"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(kernel
        .budget_store
        .get_usage(&capability.id, 0)
        .expect("forged metadata usage lookup")
        .is_none());
    assert_eq!(kernel.receipt_log().len(), 0);
}

fn make_dpop_grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    }
}

/// Build a kernel that has a DPoP store configured and a single DPoP-required grant.
fn make_dpop_kernel_and_cap(
    agent_kp: &Keypair,
    server: &str,
    tool: &str,
) -> (ChioKernel, CapabilityToken) {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "dpop-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: crate::MemoryBudgetConfig::defaults(),
        deadlines: crate::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: crate::DispatchIntentJournalMode::Off,
    };
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(EchoServer::new(server, vec![tool])));

    let nonce_store = dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300));
    kernel.set_dpop_store(nonce_store, dpop::DpopConfig::default());

    let grant = make_dpop_grant(server, tool);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    (kernel, cap)
}

/// Build a valid DPoP proof for a given request context.
fn make_dpop_proof(
    agent_kp: &Keypair,
    cap: &CapabilityToken,
    server: &str,
    tool: &str,
    arguments: &serde_json::Value,
    nonce: &str,
) -> dpop::DpopProof {
    let args_bytes =
        chio_core::canonical::canonical_json_bytes(arguments).expect("canonical_json_bytes failed");
    let action_hash = chio_core::crypto::sha256_hex(&args_bytes);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time error")
        .as_secs();
    let body = dpop::DpopProofBody {
        schema: dpop::DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: server.to_string(),
        tool_name: tool.to_string(),
        action_hash,
        nonce: nonce.to_string(),
        issued_at: now_secs,
        agent_key: agent_kp.public_key(),
    };
    dpop::DpopProof::sign(body, agent_kp).expect("DPoP sign failed")
}
