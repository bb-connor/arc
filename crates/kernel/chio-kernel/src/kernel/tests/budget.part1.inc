#[test]
fn supplemental_quota_verification_requires_an_installed_kernel_verifier() {
    let kernel = make_kernel(make_config());
    let artifact = crate::supplemental_quota::OpaqueSignedSupplementalQuota::new(
        b"signed-supplemental-artifact".to_vec(),
    )
    .unwrap();
    let context = crate::supplemental_quota::SupplementalQuotaVerificationContext {
        capability_id: "cap-supplemental".to_string(),
        capability_digest: "11".repeat(32),
        subject: Keypair::generate().public_key(),
        request_id: "request-supplemental".to_string(),
        destination: crate::supplemental_quota::SupplementalQuotaDestination::new(
            "broker", "execute",
        )
        .unwrap(),
        arguments_digest: "22".repeat(32),
        request_binding_hash: "33".repeat(32),
        now: 100,
        negotiated_profile: crate::budget_store::BudgetQuotaProfile::SupplementalBrokerExecution,
        negotiated_features: chio_core::capability::features::CapabilityNegotiation::t1_default(),
    };

    assert!(matches!(
        kernel.verify_supplemental_quota(&artifact, &context),
        Err(crate::supplemental_quota::SupplementalQuotaError::VerifierUnavailable)
    ));
}

#[test]
fn budget_exhaustion() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(2),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // First two calls succeed.
    for i in 0..2 {
        let req = make_request(&format!("req-{i}"), &cap, "read_file", "srv-a");
        let resp = kernel.evaluate_tool_call_blocking(&req).unwrap();
        assert_eq!(resp.verdict, Verdict::Allow, "call {i} should succeed");
    }

    // Third call is denied.
    let req = make_request("req-2", &cap, "read_file", "srv-a");
    let resp = kernel.evaluate_tool_call_blocking(&req).unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(reason.contains("budget"), "reason was: {reason}");
}

#[test]
fn single_invocation_budget_dispatches_once() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));

    let subject_kp = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &subject_kp, make_scope(vec![grant]), 300);

    let first = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-single-limit-1",
            &cap,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(first.verdict, Verdict::Allow);

    let second = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-single-limit-2",
            &cap,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(second.verdict, Verdict::Deny);
    assert!(second
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("budget")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
}

#[test]
fn aggregate_invocation_enforcement_disabled_denies_before_hosted_dispatch() {
    use chio_core::capability::aggregate_budget::{
        AggregateInvocationBudget, AggregateInvocationScope,
    };

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));

    let subject_kp = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let ordinary = make_capability(&kernel, &subject_kp, make_scope(vec![grant]), 300);
    let mut body = ordinary.body();
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 0,
        root_binding: None,
    });
    let aggregate = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("sign structurally valid aggregate capability");

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-unenforced-aggregate",
            &aggregate,
            "read_file",
            "srv-a",
        ))
        .expect("hosted evaluation");

    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "aggregate-bearing capability must be denied before tool server entry"
    );
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("aggregate invocation budget is not negotiated")));
    assert!(
        kernel
            .budget_store
            .get_usage(&aggregate.id, 0)
            .expect("query budget usage")
            .is_none(),
        "aggregate rollout denial must precede ordinary budget mutation"
    );
}

#[test]
fn budgets_are_tracked_per_matching_grant() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file"],
    )));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![
            ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(2),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            },
            ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "write_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            },
        ],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&make_request("read-1", &cap, "read_file", "srv-a"))
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&make_request("read-2", &cap, "read_file", "srv-a"))
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&make_request("write-1", &cap, "write_file", "srv-a"))
            .unwrap()
            .verdict,
        Verdict::Allow
    );

    let denied = kernel
        .evaluate_tool_call_blocking(&make_request("write-2", &cap, "write_file", "srv-a"))
        .unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.reason.as_deref().unwrap_or("").contains("budget"));

    let read_usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    let write_usage = kernel.budget_store.get_usage(&cap.id, 1).unwrap().unwrap();
    assert_eq!(read_usage.invocation_count, 2);
    assert_eq!(write_usage.invocation_count, 1);
}

#[test]
fn pre_dispatch_guard_denial_does_not_mutate_invocation_budget() {
    struct DenyOnce {
        denied: AtomicBool,
    }

    impl Guard for DenyOnce {
        fn name(&self) -> &str {
            "deny-once"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            if self.denied.swap(true, Ordering::SeqCst) {
                Ok(GuardDecision::allow())
            } else {
                Ok(GuardDecision::deny(Vec::new()))
            }
        }
    }

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.add_guard(Box::new(DenyOnce {
        denied: AtomicBool::new(false),
    }));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));

    let subject_kp = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &subject_kp, make_scope(vec![grant]), 300);

    let denied = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-guard-reversal-1",
            &cap,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(kernel.budget_store.get_usage(&cap.id, 0).unwrap().is_none());

    let allowed = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-guard-reversal-2",
            &cap,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(allowed.verdict, Verdict::Allow);

    let exhausted = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-guard-reversal-3",
            &cap,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(exhausted.verdict, Verdict::Deny);
    assert!(exhausted
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("budget")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn monetary_denial_exceeds_per_invocation_cap() {
    // Grant max_cost_per_invocation=100; tool server reports actual cost 150 (> cap).
    // The budget check should deny because the worst-case debit (100) passes the cap,
    // but the server reports 150 which exceeds the cap -- actually no: we charge the
    // max_cost_per_invocation as the worst-case DEBIT upfront. The per-invocation check
    // is: cost_units (=max_per) must be <= max_cost_per_invocation. With cost_units=100
    // and max_per=100 that passes. After invocation, server reports 150; we log a warning
    // and set settlement_status=failed. But the invocation is NOT denied before execution.
    //
    // To produce a pre-execution monetary denial, the requested cost must exceed the cap.
    // This happens when we charge cost_units = max_cost_per_invocation but the total budget
    // is already exhausted.
    //
    // Test: accumulated 500 + max_cost_per_invocation=100 exceeds max_total_cost=500 -> deny.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    let server = MonetaryCostServer::no_cost("cost-srv");
    kernel.register_tool_server(Box::new(server));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 500, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = |id: &str| ToolCallRequest {
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

    // 5 invocations: 5 * 100 = 500 total -- all should pass.
    for i in 0..5 {
        let resp = kernel
            .evaluate_tool_call_blocking(&request(&format!("req-{i}")))
            .unwrap();
        assert_eq!(
            resp.verdict,
            Verdict::Allow,
            "invocation {i} should be allowed"
        );
    }

    // 6th invocation would need 600 total, exceeding max_total_cost=500.
    let resp = kernel
        .evaluate_tool_call_blocking(&request("req-6"))
        .unwrap();
    assert_eq!(
        resp.verdict,
        Verdict::Deny,
        "6th invocation should be denied"
    );
}

#[test]
fn monetary_denial_receipt_contains_financial_metadata() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = ToolCallRequest {
        request_id: "req-1".to_string(),
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

    // First invocation uses up the entire budget (100 of 100).
    let _allow = kernel.evaluate_tool_call_blocking(&request).unwrap();

    // Second invocation should be denied.
    let deny_req = ToolCallRequest {
        request_id: "req-2".to_string(),
        ..request
    };
    let resp = kernel.evaluate_tool_call_blocking(&deny_req).unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);

    // Receipt must contain financial metadata.
    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    assert_eq!(financial["settlement_status"], "not_applicable");
    assert!(financial["attempted_cost"].as_u64().is_some());
    assert_eq!(financial["currency"], "USD");
    let attribution = metadata
        .get("attribution")
        .expect("should have 'attribution' key");
    assert_eq!(attribution["grant_index"].as_u64(), Some(0));
    assert!(attribution["subject_key"].as_str().is_some());
}

#[test]
fn monetary_guard_denial_releases_budget_and_records_attempted_cost() {
    use std::sync::{Arc, Mutex};

    struct DenyOnceGuard {
        denied: Arc<Mutex<bool>>,
    }

    impl Guard for DenyOnceGuard {
        fn name(&self) -> &str {
            "deny-once"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            let mut denied = self.denied.lock().unwrap();
            if !*denied {
                *denied = true;
                Ok(GuardDecision::deny(Vec::new()))
            } else {
                Ok(GuardDecision::allow())
            }
        }
    }

    let mut kernel = make_kernel(make_monetary_config());
    kernel.add_guard(Box::new(DenyOnceGuard {
        denied: Arc::new(Mutex::new(false)),
    }));
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = |request_id: &str| ToolCallRequest {
        request_id: request_id.to_string(),
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

    let denied_response = kernel
        .evaluate_tool_call_blocking(&request("req-deny"))
        .unwrap();
    assert_eq!(denied_response.verdict, Verdict::Deny);
    let denied_metadata = denied_response
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let denied_financial = denied_metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(denied_financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(denied_financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(denied_financial["budget_remaining"].as_u64(), Some(100));
    assert_eq!(denied_financial["settlement_status"], "not_applicable");

    let allowed_response = kernel
        .evaluate_tool_call_blocking(&request("req-allow"))
        .unwrap();
    assert_eq!(allowed_response.verdict, Verdict::Allow);
    let allowed_metadata = allowed_response
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let allowed_financial = allowed_metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(allowed_financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(allowed_financial["budget_remaining"].as_u64(), Some(0));
}

#[test]
fn kernel_accepts_optional_payment_adapter_installation() {
    let mut kernel = make_kernel(make_monetary_config());
    assert!(kernel.payment_adapter.is_none());

    kernel
        .set_payment_adapter(Box::new(DeterministicPaymentAdapter))
        .expect("install payment adapter");

    assert!(kernel.payment_adapter.is_some());
}

#[test]
fn monetary_payment_authorization_denial_releases_budget_and_skips_tool_invocation() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter)).expect("install payment adapter");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-payment-deny".to_string(),
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
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "tool should not run when payment authorization fails"
    );
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn monetary_prepaid_adapter_sets_payment_reference_on_allow_receipt() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(PrepaidSettledPaymentAdapter)).expect("install payment adapter");
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-prepaid".to_string(),
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
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["payment_reference"], "x402_txn_paid");
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(900));
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.committed_cost_units().unwrap(), 100);
}

#[test]
fn monetary_allow_receipt_contains_financial_metadata() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Server reports actual cost of 75 cents (< max 100).
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-1".to_string(),
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
        })
        .unwrap();

    assert_eq!(resp.verdict, Verdict::Allow);

    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    // The actual reported cost (75) should be recorded.
    assert_eq!(financial["cost_charged"].as_u64().unwrap(), 75);
    assert_eq!(financial["budget_remaining"].as_u64(), Some(925));
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["currency"], "USD");
    let attribution = metadata
        .get("attribution")
        .expect("should have 'attribution' key");
    assert_eq!(attribution["grant_index"].as_u64(), Some(0));

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.committed_cost_units().unwrap(), 75);
}

#[test]
fn monetary_allow_records_budget_hold_and_append_only_events() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-budget-event-log";
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
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
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);

    let hold_id = format!("budget-hold:{request_id}:{}:0", cap.id);
    let authorize_event_id = format!("{hold_id}:authorize");
    let reconcile_event_id = format!("{hold_id}:reconcile");
    let events = kernel
        .budget_store
        .list_mutation_events(10, Some(&cap.id), Some(0))
        .unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id.as_str()));
    assert_eq!(events[0].allowed, Some(true));
    assert_eq!(events[0].exposure_units, 100);
    assert_eq!(events[1].event_id, reconcile_event_id);
    assert_eq!(events[1].hold_id.as_deref(), Some(hold_id.as_str()));
    assert_eq!(events[1].realized_spend_units, 75);
    assert_eq!(events[1].total_cost_exposed_after, 0);
    assert_eq!(events[1].total_cost_realized_spend_after, 75);
}

#[test]
fn sibling_sum_denial_reverses_pre_execution_monetary_charge() {
    let fixture = make_sibling_sum_monetary_fixture("sibling-sum-rollback");
    let kernel = fixture.kernel;

    let allow_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-sibling-sum-rollback-a".to_string(),
            capability: fixture.child_a.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_a_kp.public_key().to_hex(),
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
    assert_eq!(
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let deny_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-sibling-sum-rollback-b".to_string(),
            capability: fixture.child_b.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_b_kp.public_key().to_hex(),
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
    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));

    let metadata = deny_response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry rollback metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1_000));

    let usage = kernel
        .budget_store
        .get_usage(&fixture.child_b.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn sibling_sum_denial_reverses_pre_execution_invocation_increment() {
    let fixture = make_sibling_sum_invocation_fixture("sibling-sum-invocation-rollback");
    let kernel = fixture.kernel;

    let allow_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-sibling-sum-invocation-rollback-a".to_string(),
            capability: fixture.child_a.clone(),
            tool_name: "compute".to_string(),
            server_id: "limited-srv".to_string(),
            agent_id: fixture.child_a_kp.public_key().to_hex(),
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
    assert_eq!(
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let deny_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-sibling-sum-invocation-rollback-b".to_string(),
            capability: fixture.child_b.clone(),
            tool_name: "compute".to_string(),
            server_id: "limited-srv".to_string(),
            agent_id: fixture.child_b_kp.public_key().to_hex(),
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
    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));

    let usage = kernel
        .budget_store
        .get_usage(&fixture.child_b.id, 0)
        .unwrap();
    assert_eq!(usage.as_ref().map_or(0, |usage| usage.invocation_count), 0);
    assert_eq!(
        usage
            .as_ref()
            .map(BudgetUsageRecord::committed_cost_units)
            .transpose()
            .unwrap()
            .unwrap_or(0),
        0
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn nested_hosted_sibling_sum_denial_reverses_pre_execution_monetary_charge() {
    let fixture = make_sibling_sum_monetary_fixture("nested-sibling-sum-rollback");
    let kernel = fixture.kernel;
    let session_id = kernel
        .open_session("nested-parent-agent".to_string(), Vec::new())
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_context = make_operation_context(
        &session_id,
        "req-nested-sibling-sum-parent",
        "nested-parent-agent",
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };

    let allow_response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-nested-sibling-sum-rollback-a".to_string(),
                capability: fixture.child_a.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: fixture.child_a_kp.public_key().to_hex(),
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
            },
            &mut client,
            None,
        )
        .unwrap();
    assert_eq!(
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let deny_response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-nested-sibling-sum-rollback-b".to_string(),
                capability: fixture.child_b.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: fixture.child_b_kp.public_key().to_hex(),
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
            },
            &mut client,
            None,
        )
        .unwrap();
    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));

    let metadata = deny_response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry rollback metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1_000));

    let usage = kernel
        .budget_store
        .get_usage(&fixture.child_b.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn payment_authorization_denial_releases_delegated_sibling_budget() {
    let fixture = make_sibling_sum_monetary_fixture("delegated-payment-deny-budget");
    let mut kernel = fixture.kernel;
    kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter)).expect("install payment adapter");

    let denied_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-delegated-payment-deny-a".to_string(),
            capability: fixture.child_a.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_a_kp.public_key().to_hex(),
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
    assert_eq!(denied_response.verdict, Verdict::Deny);
    assert!(denied_response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("payment authorization failed")));

    kernel
        .set_payment_adapter(Box::new(DeterministicPaymentAdapter))
        .expect("install payment adapter");
    let allowed_sibling = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-delegated-payment-deny-b".to_string(),
            capability: fixture.child_b.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_b_kp.public_key().to_hex(),
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
    assert_eq!(
        allowed_sibling.verdict,
        Verdict::Allow,
        "payment-denied child must not starve a later sibling: {:?}",
        allowed_sibling.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn nested_payment_authorization_denial_releases_delegated_sibling_budget() {
    let fixture = make_sibling_sum_monetary_fixture("nested-delegated-payment-deny-budget");
    let mut kernel = fixture.kernel;
    kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter)).expect("install payment adapter");
    let session_id = kernel.open_session("nested-parent-agent".to_string(), Vec::new()).unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_context = make_operation_context(
        &session_id,
        "req-nested-payment-deny-parent",
        "nested-parent-agent",
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };

    let denied_response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-nested-payment-deny-a".to_string(),
                capability: fixture.child_a.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: fixture.child_a_kp.public_key().to_hex(),
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
            },
            &mut client,
            None,
        )
        .unwrap();
    assert_eq!(denied_response.verdict, Verdict::Deny);
    assert!(denied_response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("payment authorization failed")));

    kernel
        .set_payment_adapter(Box::new(DeterministicPaymentAdapter))
        .expect("install payment adapter");
    let allowed_sibling = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-nested-payment-deny-b".to_string(),
                capability: fixture.child_b.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: fixture.child_b_kp.public_key().to_hex(),
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
            },
            &mut client,
            None,
        )
        .unwrap();
    assert_eq!(
        allowed_sibling.verdict,
        Verdict::Allow,
        "nested payment-denied child must not starve a later sibling: {:?}",
        allowed_sibling.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn hosted_named_remote_without_fresh_peer_fails_before_dispatch() {
    let fixture = make_sibling_sum_monetary_fixture("missing-remote-peer");
    let kernel = fixture.kernel;

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-missing-remote-peer".to_string(),
            capability: fixture.child_a.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_a_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            federated_origin_kernel_id: Some("stale-or-missing-peer".to_string()),
            declassification_grant: None,
        })
        .expect("missing peer must produce a structured Deny response");

    // The kernel returns a signed Deny ToolCallResponse for the
    // named-peer-not-pinned-fresh case BEFORE dispatch, instead of
    // propagating an Err out of `evaluate_tool_call_blocking`. The Err
    // propagation form was unsafe: callers could miss it and the
    // receipt-store invariant would not be satisfied.
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("receipt negotiation downgrade") || reason.contains("not pinned fresh"),
        "unexpected deny reason: {reason}"
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn portable_subject_denial_does_not_consume_sibling_budget() {
    let fixture = make_sibling_sum_monetary_fixture("portable-subject-deny-budget");
    let kernel = fixture.kernel;
    let clock = chio_kernel_core::FixedClock::new(current_unix_timestamp());
    let guards: [&dyn chio_kernel_core::Guard; 0] = [];

    let wrong_subject = chio_kernel_core::PortableToolCallRequest {
        request_id: "req-portable-wrong-subject".to_string(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: fixture.child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
    };
    let denied =
        kernel.evaluate_portable_verdict(&fixture.child_a, &wrong_subject, &guards, &clock, None);
    assert_eq!(denied.verdict, chio_kernel_core::Verdict::Deny);

    let valid_sibling = chio_kernel_core::PortableToolCallRequest {
        request_id: "req-portable-valid-sibling".to_string(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: fixture.child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
    };
    let allowed =
        kernel.evaluate_portable_verdict(&fixture.child_b, &valid_sibling, &guards, &clock, None);
    assert_eq!(allowed.verdict, chio_kernel_core::Verdict::Allow);

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn monetary_allow_receipt_marks_failed_settlement_when_reported_cost_exceeds_charge() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 150, "USD")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-overrun".to_string(),
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
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    assert_eq!(financial["cost_charged"].as_u64(), Some(150));
    assert_eq!(financial["settlement_status"], "failed");
    assert!(financial["payment_reference"].is_null());
}

#[test]
fn monetary_server_not_reporting_cost_charges_max_cost_per_invocation() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Server does NOT report cost (returns None).
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-1".to_string(),
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
        })
        .unwrap();

    assert_eq!(resp.verdict, Verdict::Allow);
    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    // Worst-case debit: max_cost_per_invocation = 100.
    assert_eq!(financial["cost_charged"].as_u64().unwrap(), 100);
}

#[test]
fn monetary_dispatch_failure_keeps_invocation_consumed() {
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&invocations),
    )));

    let subject_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel
        .issue_capability(&subject_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = |request_id: &str| make_request(request_id, &cap, "compute", "cost-srv");

    let failed = kernel
        .evaluate_tool_call_blocking(&request("req-dispatch-failure-1"))
        .unwrap();
    assert_eq!(failed.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.invocation_count, 1,
        "a dispatch failure must retain the consumed invocation"
    );
    assert_eq!(usage.total_cost_exposed, 0);
    let terminal = &failed.receipt.metadata.as_ref().unwrap()["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert_eq!(terminal["committed_cost_units_after"], 0);
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));

    let retry = kernel
        .evaluate_tool_call_blocking(&request("req-dispatch-failure-2"))
        .unwrap();
    assert_eq!(retry.verdict, Verdict::Deny);
    assert!(retry
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("budget")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn unmeasured_cost_server_reverses_hold_and_signs_provisional_receipt() {
    // A tool server that does not measure realized cost (a pre-execution
    // authorization gate that dispatches a pass-through while the real tool
    // runs elsewhere) must not yield a settled, reconciled authoritative spend.
    // The kernel reverses the pre-execution hold and signs a provisional,
    // unreconciled receipt: settlement is pending, the terminal disposition is
    // "reversed", and no committed cost is moved.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(UnmeasuredCostServer {
        id: "gate-srv".to_string(),
    }));

    let grant = make_monetary_grant("gate-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-unmeasured".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "gate-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();

    assert_eq!(resp.verdict, Verdict::Allow);
    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    // No realized cost measured: nothing charged and settlement stays pending.
    assert_eq!(financial["cost_charged"].as_u64().unwrap(), 0);
    assert_eq!(financial["settlement_status"], "pending");

    let budget_authority = metadata
        .get("budget_authority")
        .expect("should have 'budget_authority' key");
    assert_eq!(budget_authority["terminal"]["disposition"], "reversed");
    assert_ne!(budget_authority["terminal"]["disposition"], "reconciled");

    // The hold is reversed, so no committed cost is moved.
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn unmeasured_cost_provisional_allow_emits_no_execution_nonce() {
    // The provisional unmeasured-cost allow path reverses the pre-execution
    // budget hold and does not execute the target tool at the kernel. On a
    // nonce-enabled kernel it must emit no execution nonce: there is no reserved
    // hold to reconcile and nothing to authorize downstream. A minted nonce here
    // would carry no reserved hold, so a gate deployment could execute against a
    // hold that was already refunded, spending outside the cumulative cap and
    // leaving the spend unreconcilable. The measured-cost allow path on the same
    // kernel must still mint a nonce, guarding against over-suppression.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(UnmeasuredCostServer {
        id: "gate-srv".to_string(),
    }));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 50, "USD")));

    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");

    let scope = make_scope(vec![
        make_monetary_grant("gate-srv", "compute", 100, 1000, "USD"),
        make_monetary_grant("cost-srv", "compute", 100, 1000, "USD"),
    ]);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 3600)
        .unwrap();

    // Provisional unmeasured-cost Value path: allow, but no execution nonce.
    let provisional = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-unmeasured-nonce".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "gate-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();
    assert_eq!(provisional.verdict, Verdict::Allow);
    assert!(
        provisional.execution_nonce.is_none(),
        "provisional unmeasured allow reversed its hold; it must not mint a spendable nonce"
    );

    // Measured-cost Value path on the same nonce-enabled kernel: allow, and a
    // nonce is minted so a real reserved spend can be authorized downstream.
    let measured = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-measured-nonce".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();
    assert_eq!(measured.verdict, Verdict::Allow);
    assert!(
        measured.execution_nonce.is_some(),
        "measured-cost allow must still mint an execution nonce"
    );
}

#[test]
fn monetary_tool_server_error_releases_precharged_budget() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(FailingMonetaryServer {
        id: "cost-srv".to_string(),
    }));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-tool-error".to_string(),
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
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
    let terminal = &response.receipt.metadata.as_ref().unwrap()["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
}
