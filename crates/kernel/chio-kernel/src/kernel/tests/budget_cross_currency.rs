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
            supplemental_authorization: None,
            model_metadata: None,
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
            supplemental_authorization: None,
            model_metadata: None,
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
