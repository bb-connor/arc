use super::*;
use chio_mcp_adapter::edge::{McpToolInfo, McpToolResult, McpTransport};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct ObservedChild {
    calls: Arc<AtomicUsize>,
    result: McpToolResult,
}
impl McpTransport for ObservedChild {
    fn list_tools(&self) -> Result<Vec<McpToolInfo>, chio_mcp_adapter::edge::AdapterError> {
        ["http_request", "echo"].into_iter().map(|name| {
            serde_json::from_value(serde_json::json!({"name": name, "inputSchema": {"type":"object"}, "annotations":{"readOnlyHint":true}}))
                .map_err(|error| chio_mcp_adapter::edge::AdapterError::ParseError(error.to_string()))
        }).collect()
    }
    fn call_tool(
        &self,
        _: &str,
        _: serde_json::Value,
    ) -> Result<McpToolResult, chio_mcp_adapter::edge::AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.result.clone())
    }
}
fn wrapped_child(text: &str) -> TestResult<(KernelMediatedMcpTransport, Arc<AtomicUsize>)> {
    let calls = Arc::new(AtomicUsize::new(0));
    let result =
        serde_json::from_value(serde_json::json!({"content":[{"type":"text","text":text}]}))?;
    let transport = KernelMediatedMcpTransport::new(
        "product-test",
        "product-test",
        "1",
        Box::new(ObservedChild {
            calls: calls.clone(),
            result,
        }),
        &std::collections::BTreeSet::from(["http_request".into(), "echo".into()]),
    )?;
    Ok((transport, calls))
}

#[test]
fn product_default_guards_wrap_denies_internal_network_before_child_effect() -> TestResult {
    let (transport, calls) = wrapped_child("healthy output")?;
    let frame = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"http://169.254.169.254/latest/meta-data"}}}).to_string()+"\n";
    let gate = ManifestVerdictGate {
        allowed: std::collections::BTreeSet::from(["http_request".into()]),
    };
    let mut out = Vec::new();
    run_wrap_with_gate(&transport, &gate, frame.as_bytes(), &mut out)?;
    let reply: serde_json::Value = serde_json::from_slice(&out)?;
    assert!(
        reply.get("error").is_some(),
        "private target reached child: {reply}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let receipts = transport.kernel.receipt_log().receipts();
    assert!(!receipts.is_empty());
    assert!(receipts
        .iter()
        .all(|receipt| receipt.verify_signature().unwrap_or(false)));
    assert!(receipts.iter().any(|receipt| matches!(
        receipt.decision.as_ref(),
        Some(chio_core::receipt::decision::Decision::Deny { .. })
    )));
    Ok(())
}

#[test]
fn product_default_guards_wrap_sanitizes_observed_output_with_signed_hook_evidence() -> TestResult {
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB";
    let (transport, calls) = wrapped_child(&format!("credential {secret}"))?;
    let output = transport.call_tool("echo", serde_json::json!({"text":"hello"}))?;
    let bytes = serde_json::to_string(&output)?;
    assert!(!bytes.contains(secret), "unredacted output: {bytes}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let receipts = transport.kernel.receipt_log().receipts();
    let receipt = receipts
        .iter()
        .find(|receipt| {
            receipt
                .evidence
                .iter()
                .any(|evidence| evidence.guard_name == "output-sanitizer")
        })
        .ok_or("observed redaction lacks signed hook evidence")?;
    assert_eq!(receipt.kernel_key, transport.kernel.public_key());
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.policy_hash, transport.kernel.policy_hash());
    assert_eq!(receipt.policy_hash.len(), 64);
    assert!(receipt
        .evidence
        .iter()
        .any(|evidence| evidence.guard_name == "output-sanitizer" && evidence.verdict));
    assert!(!serde_json::to_string(receipt)?.contains(secret));
    // The default advisory roster is empty; it cannot invent detector signals
    // or promote an observation into a blocking decision.
    assert!(!receipt.evidence.iter().any(|evidence| evidence
        .details
        .as_deref()
        .is_some_and(|details| details.contains("promoted=true"))));
    assert_eq!(
        transport.kernel.guard_names(),
        ["internal-network", "agent-velocity", "advisory-pipeline"]
    );
    assert_eq!(
        transport.kernel.post_invocation_hook_names(),
        ["output-sanitizer"]
    );
    Ok(())
}
