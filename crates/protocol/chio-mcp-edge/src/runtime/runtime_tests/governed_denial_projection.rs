use super::*;
use chio_core::receipt::body::ChioReceipt;

fn governed_error_result() -> Value {
    json!({
        "content": [{"type": "text", "text": "Governed transaction denied"}],
        "structuredContent": {"code": "governed_transaction_denied"},
        "isError": true,
    })
}

#[test]
fn typed_governed_errors_project_a_fixed_client_code_and_text() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge(10);
    for detail in [
        "/private/operator/policy.json",
        "Bearer secret-token",
        "unknown detail",
        "",
    ] {
        let outcome = edge.tool_call_error_outcome(
            &SessionId::new("governed-projection"),
            KernelError::GovernedTransactionDenied(detail.to_string()),
            None,
        );
        let ToolCallEdgeOutcome::Result(result) = outcome else {
            panic!("governed denial did not produce a tool result");
        };
        assert_eq!(result, governed_error_result());
    }
}

#[test]
fn non_governed_error_text_cannot_select_the_governed_projection() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge(10);
    let error =
        KernelError::InvalidConstraint("governed transaction denied: arbitrary".to_string());
    let expected = error.to_string();
    let outcome = edge.tool_call_error_outcome(&SessionId::new("other-projection"), error, None);
    let ToolCallEdgeOutcome::Result(result) = outcome else {
        panic!("constraint refusal did not produce a tool result");
    };
    assert_eq!(result["content"][0]["text"], expected);
    assert!(result.get("structuredContent").is_none());
}

#[test]
fn governed_denial_display_preserves_the_real_signed_receipt() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, signer) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    initialize_edge(&mut edge);
    let mut request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/input.txt"}}
    });
    let control = edge.handle_jsonrpc(request.clone()).unwrap();
    assert_eq!(control["result"]["isError"], false);
    request["id"] = json!(2);
    request["params"]["_meta"] = json!({"chioGovernedIntent": {
        "id": "intent:chio:projection", "server_id": "other-server",
        "tool_name": "read_file", "purpose": "target-binding control"
    }});
    let response = edge.handle_jsonrpc(request).unwrap();
    let result = &response["result"];
    let receipt: ChioReceipt =
        serde_json::from_value(result["_meta"]["chioEvidence"]["receipt"].clone()).unwrap();
    assert_eq!(receipt.kernel_key, signer.public_key());
    assert!(receipt.verify_integrity_embedded_key().unwrap());
    let expected_error = KernelError::GovernedTransactionDenied(
        "governed transaction intent target does not match the tool call".to_string(),
    );
    assert_eq!(
        result["_meta"]["chioEvidence"]["receipt"]["decision"]["reason"],
        expected_error.to_string()
    );
    assert_eq!(
        result["_meta"]["chioEvidence"]["receipt"]["metadata"]["chio_kernel"]["rejection_code"],
        expected_error.report().code
    );
    assert_eq!(
        result["_meta"]["chio"]["receipt"],
        result["_meta"]["chioEvidence"]["receipt"]
    );
    let stored = edge.kernel.receipt_log().receipts();
    assert_eq!(
        serde_json::to_value(stored.last().unwrap()).unwrap(),
        result["_meta"]["chioEvidence"]["receipt"]
    );
    assert_eq!(result["_meta"]["chioEvidence"]["outputKind"], "none");
    assert!(result["_meta"]["chioEvidence"]["output"].is_null());
    let expected = governed_error_result();
    assert_eq!(result["isError"], expected["isError"]);
    assert_eq!(result["content"], expected["content"]);
    assert_eq!(result["structuredContent"], expected["structuredContent"]);
}

#[test]
fn typed_governed_failure_notifications_project_generic_text() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge_with_config(10, true);
    let error = KernelError::GovernedTransactionDenied("Bearer secret-token".to_string());
    let outcome =
        edge.tool_call_error_outcome(&SessionId::new("notification-projection"), error, None);
    let notifications = edge.take_pending_notifications();
    assert_eq!(
        notifications,
        vec![json!({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": "error",
                "logger": "chio.mcp.tools",
                "data": {"event": "tool_failed", "error": "Governed transaction denied"},
            },
        })]
    );
    let ToolCallEdgeOutcome::Result(result) = outcome else {
        panic!("governed denial did not produce a tool result");
    };
    assert_eq!(result, governed_error_result());
}

#[test]
fn other_failure_notifications_preserve_their_error_text() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge_with_config(10, true);
    let error =
        KernelError::InvalidConstraint("governed transaction denied: arbitrary".to_string());
    let expected = error.to_string();
    let outcome = edge.tool_call_error_outcome(&SessionId::new("other-notification"), error, None);
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["params"]["data"]["error"], expected);
    let ToolCallEdgeOutcome::Result(result) = outcome else {
        panic!("constraint refusal did not produce a tool result");
    };
    assert_eq!(result["content"][0]["text"], expected);
    assert!(result.get("structuredContent").is_none());
}
