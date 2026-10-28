use super::*;

const PRIVATE_DETAIL: &str = "call_chain.parent_request_id must not equal the current request_id";

#[test]
fn governed_denial_receipt_carries_code_and_commitment_without_detail() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-deny-code";
    let mut intent = make_governed_intent(
        "intent-governed-deny-code",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-deny-code",
        request_id,
    ));
    bind_test_tool_approval(
        &mut kernel,
        &cap,
        &serde_json::json!({ "invoice_id": "inv-1001" }),
        request_id,
        &mut intent,
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("governed transaction denied")
    );

    let receipt = serde_json::to_value(&response.receipt).unwrap();
    let decision = &receipt["decision"];
    assert_eq!(decision["verdict"], "deny", "decision: {decision}");
    assert_eq!(decision["code"], "governed_denied", "decision: {decision}");
    assert_eq!(decision["reason"], "governed transaction denied");
    let commitment = decision["detail_commitment"].as_str().unwrap_or_default();
    assert_eq!(commitment.len(), 64, "decision: {decision}");

    let signed = serde_json::to_string(&response.receipt).unwrap();
    assert!(
        !signed.contains(PRIVATE_DETAIL),
        "detail leaked into the receipt"
    );
    assert!(
        !signed.contains("\"chio_kernel\""),
        "rejection_code metadata remains"
    );
}
