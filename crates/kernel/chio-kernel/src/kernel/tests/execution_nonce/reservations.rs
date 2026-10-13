use super::*;

#[test]
fn mediated_allow_receipt_records_bound_execution_nonce_id() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-nonce-link".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let nonce = response
        .execution_nonce
        .as_ref()
        .expect("mediated allow mints a nonce");
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    let recorded = metadata["budget_authority"]["execution_nonce_id"]
        .as_str()
        .expect("execution_nonce_id recorded on budget_authority metadata");
    assert_eq!(recorded, nonce.nonce_id());
    assert_eq!(
        metadata["budget_authority"]["mediated_spend"]["profile"],
        "chio.mediated_spend.v1"
    );
}

#[test]
fn strict_retry_mediated_spend_receipt_names_presented_nonce() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let mut request = ToolCallRequest {
        request_id: "req-strict-retry-nonce".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    // The strict retry presents a nonce from a prior allow (the nonce binds the
    // capability/server/tool/parameter-hash, not the request id), so no nonce is
    // preminted during this completion.
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    request.execution_nonce = Some(nonce.clone());
    let executed = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(
        executed.output.is_some(),
        "strict retry must return tool output"
    );
    assert!(
        executed.execution_nonce.is_none(),
        "strict retry must not mint another nonce"
    );

    // The completed receipt must name the presented nonce id, not drop it.
    let metadata = executed
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["execution_nonce_id"]
            .as_str()
            .expect("execution_nonce_id recorded on budget_authority metadata"),
        nonce.nonce_id()
    );

    // The reconciled receipt is an authoritative mediated-spend receipt bound to
    // the presented nonce: no NonceLinkMissing.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&executed.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn dispatch_for_unregistered_tool_server_still_denies() {
    // The dispatch path (and every non-reserve disposition) must still require the
    // tool server to be registered: only the reserve-for-caller path is relaxed.
    let kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Non-strict kernel so the normal dispatch path (not the reserve preflight) runs.
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-dispatch".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not registered")),
        "dispatch to an unregistered server must deny ToolNotRegistered, got: {:?}",
        denied.reason
    );
}

#[test]
fn preflight_retry_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-preflight-reason", &cap, "read_file", "srv-a");

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);

    let terminal_reason = match &preflight.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("strict preflight must be incomplete, got {other:?}"),
    };
    let decision_reason = match preflight.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("strict preflight receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the retry path terminal_state reason must match its receipt decision reason"
    );
    assert_eq!(
        terminal_reason, "execution nonce preflight requires retry with presented nonce",
        "the reverse-for-retry preflight reason must be unchanged"
    );
}
