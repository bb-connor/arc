fn assert_monetary_post_dispatch_error_releases_exposure(
    server: Box<dyn ToolServerConnection>,
    server_entries: std::sync::Arc<AtomicU64>,
    request_id: &str,
    nested: bool,
) {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(server);
    let subject_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel
        .issue_capability(&subject_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = make_request(request_id, &cap, "compute", "cost-srv");

    let response = if nested {
        let session_id = kernel
            .open_session(subject_kp.public_key().to_hex(), vec![cap.clone()])
            .unwrap();
        kernel.activate_session(&session_id).unwrap();
        let context =
            make_operation_context(&session_id, request_id, &subject_kp.public_key().to_hex());
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(async {
                let mut client = NoopNestedFlowClient;
                kernel
                    .evaluate_tool_call_with_nested_flow_client_async(
                        &context,
                        &request,
                        &mut client,
                        None,
                    )
                    .await
            })
            .unwrap()
    } else {
        kernel.evaluate_tool_call_blocking(&request).unwrap()
    };

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(server_entries.load(Ordering::SeqCst), 1);
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert!(!kernel
        .budget_store
        .try_increment(&cap.id, 0, Some(1))
        .unwrap());

    let terminal = &response.receipt.metadata.as_ref().unwrap()["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert_eq!(terminal["exposure_units"], 100);
    assert_eq!(terminal["committed_cost_units_after"], 0);
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
}

#[test]
fn monetary_cancelled_connector_error_releases_exposure_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-cancelled-top-level",
        false,
    );
}

#[test]
fn monetary_incomplete_connector_error_releases_exposure_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-incomplete-top-level",
        false,
    );
}

#[test]
fn monetary_generic_connector_error_releases_exposure_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-generic-top-level",
        false,
    );
}

#[test]
fn monetary_cancelled_connector_error_releases_exposure_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-cancelled-nested",
        true,
    );
}

#[test]
fn monetary_incomplete_connector_error_releases_exposure_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-incomplete-nested",
        true,
    );
}

#[test]
fn monetary_generic_connector_error_releases_exposure_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-generic-nested",
        true,
    );
}

#[derive(Clone, Copy)]
enum CleanupFailureSource {
    Payment,
    BudgetStore,
}

#[derive(Clone, Copy)]
enum CleanupFailureTerminal {
    Cancelled,
    Incomplete,
    Denied,
}

fn assert_post_dispatch_cleanup_failure_projection(
    server: Box<dyn ToolServerConnection>,
    server_entries: std::sync::Arc<AtomicU64>,
    request_id: &str,
    nested: bool,
    source: CleanupFailureSource,
    terminal: CleanupFailureTerminal,
) {
    let mut kernel = make_kernel(make_monetary_config());
    match source {
        CleanupFailureSource::Payment => {
            kernel.set_payment_adapter(Box::new(FailingReleasePaymentAdapter));
        }
        CleanupFailureSource::BudgetStore => {
            kernel
                .set_budget_store_handle(std::sync::Arc::new(FailingReleaseBudgetStore::new()))
                .expect("budget store");
        }
    }
    kernel.register_tool_server(server);

    let subject_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel
        .issue_capability(&subject_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = make_request(request_id, &cap, "compute", "cost-srv");

    let response = if nested {
        let session_id = kernel
            .open_session(subject_kp.public_key().to_hex(), vec![cap.clone()])
            .unwrap();
        kernel.activate_session(&session_id).unwrap();
        let context =
            make_operation_context(&session_id, request_id, &subject_kp.public_key().to_hex());
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(async {
                let mut client = NoopNestedFlowClient;
                kernel
                    .evaluate_tool_call_with_nested_flow_client_async(
                        &context,
                        &request,
                        &mut client,
                        None,
                    )
                    .await
            })
            .expect("cleanup failure must preserve the connector terminal response")
    } else {
        kernel
            .evaluate_tool_call_blocking(&request)
            .expect("cleanup failure must preserve the connector terminal response")
    };

    assert_eq!(server_entries.load(Ordering::SeqCst), 1);
    match terminal {
        CleanupFailureTerminal::Cancelled => assert!(response.receipt.is_cancelled()),
        CleanupFailureTerminal::Incomplete => assert!(response.receipt.is_incomplete()),
        CleanupFailureTerminal::Denied => assert!(response.receipt.is_denied()),
    }

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);

    let metadata = response.receipt.metadata.as_ref().unwrap();
    assert!(metadata["budget_authority"]["terminal"].is_null());
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_cleanup_failed"],
        true
    );
    let faults = metadata["chio_runtime"]["post_dispatch_cleanup_faults"]
        .as_array()
        .unwrap();
    assert_eq!(faults.len(), 1);
    let fault = &faults[0];
    let expected_step = match source {
        CleanupFailureSource::Payment => "payment_release",
        CleanupFailureSource::BudgetStore => "budget_hold_release",
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
    if matches!(source, CleanupFailureSource::Payment) {
        assert!(hold_ids.iter().any(|id| id == "auth_failing_release"));
    }
}

#[test]
fn post_dispatch_cleanup_failure_rejects_forged_budget_authority() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(FailingReleasePaymentAdapter));
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&entries),
    )));

    let subject_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &subject_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )
        .unwrap();
    let request = make_request(
        "req-cleanup-fault-forged-budget-authority",
        &cap,
        "compute",
        "cost-srv",
    );

    let response = kernel
        .evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(forged_budget_authority_metadata()),
        )
        .expect("cleanup failure must preserve the connector denial");
    assert!(response.receipt.is_denied());
    assert_eq!(entries.load(Ordering::SeqCst), 1);
    let metadata = response.receipt.metadata.as_ref().unwrap();
    assert_forged_budget_authority_removed(metadata);
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_cleanup_faults"][0]["step"],
        "payment_release"
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_cancelled_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-cancelled-top",
        false,
        CleanupFailureSource::Payment,
        CleanupFailureTerminal::Cancelled,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_incomplete_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-incomplete-top",
        false,
        CleanupFailureSource::BudgetStore,
        CleanupFailureTerminal::Incomplete,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_denied_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-denied-top",
        false,
        CleanupFailureSource::Payment,
        CleanupFailureTerminal::Denied,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_cancelled_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-cancelled-nested",
        true,
        CleanupFailureSource::BudgetStore,
        CleanupFailureTerminal::Cancelled,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_incomplete_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-incomplete-nested",
        true,
        CleanupFailureSource::Payment,
        CleanupFailureTerminal::Incomplete,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_denied_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-denied-nested",
        true,
        CleanupFailureSource::BudgetStore,
        CleanupFailureTerminal::Denied,
    );
}

#[test]
fn monetary_full_pipeline_three_invocations_third_denied() {
    // max_total_cost=250, max_cost_per_invocation=100.
    // Invocation 1: charges 100, total = 100. Allowed.
    // Invocation 2: charges 100, total = 200. Allowed.
    // Invocation 3: would charge 100, total would be 300 > 250. Denied.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 250, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let make_req = |id: &str| ToolCallRequest {
        request_id: id.to_string(),
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

    let r1 = kernel
        .evaluate_tool_call_blocking(&make_req("req-1"))
        .unwrap();
    assert_eq!(r1.verdict, Verdict::Allow, "first invocation should pass");

    let r2 = kernel
        .evaluate_tool_call_blocking(&make_req("req-2"))
        .unwrap();
    assert_eq!(r2.verdict, Verdict::Allow, "second invocation should pass");

    let r3 = kernel
        .evaluate_tool_call_blocking(&make_req("req-3"))
        .unwrap();
    assert_eq!(
        r3.verdict,
        Verdict::Deny,
        "third invocation should be denied"
    );

    // Verify the denial receipt has financial metadata.
    let metadata = r3.receipt.metadata.as_ref().expect("should have metadata");
    assert!(metadata.get("financial").is_some());
}

#[test]
fn multi_grant_budget_remaining_uses_matched_grant_total() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant_a = make_monetary_grant("cost-srv", "compute-a", 100, 500, "USD");
    let grant_b = make_monetary_grant("cost-srv", "compute-b", 40, 200, "USD");
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![grant_a, grant_b]),
            3600,
        )
        .unwrap();

    let invoke = |request_id: &str, tool_name: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: tool_name.to_string(),
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

    let _ = kernel
        .evaluate_tool_call_blocking(&invoke("req-a", "compute-a"))
        .unwrap();
    let response_b = kernel
        .evaluate_tool_call_blocking(&invoke("req-b", "compute-b"))
        .unwrap();

    let metadata = response_b
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(financial["grant_index"].as_u64(), Some(1));
    assert_eq!(financial["cost_charged"].as_u64(), Some(40));
    assert_eq!(financial["budget_total"].as_u64(), Some(200));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(160));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_evaluate_tool_call_supports_shared_kernel_concurrency() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    struct ConcurrentServer {
        barrier: Arc<Barrier>,
        current: Arc<AtomicUsize>,
        max_concurrent: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for ConcurrentServer {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        async fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            assert_eq!(tool_name, "echo");

            let concurrent = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            let _ =
                self.max_concurrent
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |observed| {
                        (concurrent > observed).then_some(concurrent)
                    });

            self.barrier.wait();
            std::thread::sleep(Duration::from_millis(25));
            self.current.fetch_sub(1, Ordering::SeqCst);

            Ok(arguments)
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let mut configured_kernel = make_kernel(make_config());
    configured_kernel.register_tool_server(Box::new(ConcurrentServer {
        barrier: barrier.clone(),
        current: Arc::new(AtomicUsize::new(0)),
        max_concurrent: max_concurrent.clone(),
    }));

    let agent_kp = Keypair::generate();
    let capability = configured_kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "echo".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }]),
            3600,
        )
        .unwrap();

    let kernel = Arc::new(configured_kernel);
    let make_request = |request_id: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "request_id": request_id }),
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

    let thread_a = {
        let kernel = kernel.clone();
        let request = make_request("req-a");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move { kernel.evaluate_tool_call(&request).await })
        })
    };
    let thread_b = {
        let kernel = kernel.clone();
        let request = make_request("req-b");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move { kernel.evaluate_tool_call(&request).await })
        })
    };

    let (response_a, response_b) = tokio::time::timeout(Duration::from_secs(2), async move {
        let response_a = thread_a.join().expect("thread a should not panic");
        let response_b = thread_b.join().expect("thread b should not panic");
        (response_a, response_b)
    })
    .await
    .expect("shared kernel evaluation should not deadlock");

    let response_a = response_a.unwrap();
    let response_b = response_b.unwrap();
    assert_eq!(response_a.verdict, Verdict::Allow);
    assert_eq!(response_b.verdict, Verdict::Allow);
    assert!(
        max_concurrent.load(Ordering::SeqCst) >= 2,
        "expected concurrent server invocations on a shared kernel"
    );
}

#[test]
fn tool_invocation_cost_serde_roundtrip() {
    let cost = ToolInvocationCost {
        units: 500,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let json = serde_json::to_string(&cost).unwrap();
    let restored: ToolInvocationCost = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.units, 500);
    assert_eq!(restored.currency, "USD");
    assert!(restored.breakdown.is_none());

    // With breakdown
    let cost_with = ToolInvocationCost {
        units: 200,
        currency: "EUR".to_string(),
        breakdown: Some(serde_json::json!({"compute": 150, "network": 50})),
    };
    let json_with = serde_json::to_string(&cost_with).unwrap();
    let restored_with: ToolInvocationCost = serde_json::from_str(&json_with).unwrap();
    assert_eq!(restored_with.units, 200);
    assert!(restored_with.breakdown.is_some());
}

#[test]
fn cross_currency_reported_cost_attaches_oracle_evidence_and_converted_units() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_price_oracle(Box::new(StaticPriceOracle::new([(
        ("ETH".to_string(), "USD".to_string()),
        Ok(ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: 300_000,
            rate_denominator: 100,
            updated_at: now.saturating_sub(45),
            fetched_at: now,
            source: "chainlink".to_string(),
            feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }),
    )])));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        1_000_000_000_000_000,
        "ETH",
    )));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-cross-currency-ok".to_string(),
            capability: cap,
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
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("metadata");
    let financial = metadata.get("financial").expect("financial");
    assert_eq!(financial["cost_charged"].as_u64(), Some(306));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(694));
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["oracle_evidence"]["base"], "ETH");
    assert_eq!(financial["oracle_evidence"]["quote"], "USD");
    assert_eq!(
        financial["oracle_evidence"]["converted_cost_units"].as_u64(),
        Some(306)
    );
    assert_eq!(
        financial["cost_breakdown"]["oracle_conversion"]["status"],
        "applied"
    );
}

#[test]
fn cross_currency_without_oracle_keeps_provisional_charge_and_marks_failed_settlement() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        1_000_000_000_000_000,
        "ETH",
    )));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-cross-currency-failed".to_string(),
            capability: cap,
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
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("metadata");
    let financial = metadata.get("financial").expect("financial");
    assert_eq!(financial["cost_charged"].as_u64(), Some(400));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(600));
    assert_eq!(financial["settlement_status"], "failed");
    assert!(financial.get("oracle_evidence").is_none());
    assert_eq!(
        financial["cost_breakdown"]["oracle_conversion"]["status"],
        "failed"
    );
}

#[tokio::test]
async fn echo_server_invoke_with_cost_returns_none() {
    let server = EchoServer::new("srv-a", vec!["echo"]);
    let args = serde_json::json!({"msg": "hello"});
    let (value, cost) = server
        .invoke_with_cost("echo", args, None)
        .await
        .expect("invoke_with_cost should succeed");
    assert!(cost.is_none(), "EchoServer should return None cost");
    assert!(value.is_object());
}

// ---------------------------------------------------------------------------
// DPoP wiring tests
// ---------------------------------------------------------------------------
