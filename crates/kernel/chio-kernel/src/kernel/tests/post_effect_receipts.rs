use super::*;

struct InvalidOutputHook(serde_json::Value);

impl crate::post_invocation::PostInvocationHook for InvalidOutputHook {
    fn name(&self) -> &str {
        "invalid-output-envelope"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Redact(self.0.clone())
    }
}

fn fixture() -> (ChioKernel, ToolCallRequest, Arc<AtomicU64>) {
    let mut kernel = make_kernel(make_config());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "receipt-test",
        vec!["read_file"],
        Arc::clone(&invocations),
    )));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("receipt-test", "read_file")]),
        300,
    );
    let request = make_request(
        "post-effect-receipt",
        &capability,
        "read_file",
        "receipt-test",
    );
    (kernel, request, invocations)
}

fn assert_failed_finalization_is_receipted(envelope: serde_json::Value) {
    let (mut kernel, request, invocations) = fixture();
    kernel.add_post_invocation_hook(Box::new(InvalidOutputHook(envelope)));
    let result = kernel.evaluate_tool_call_blocking(&request);
    assert_eq!(invocations.load(Ordering::SeqCst), 1, "tool must execute");
    let receipts = kernel.receipt_log();
    assert_eq!(
        receipts.len(),
        1,
        "an executed call must retain exactly one terminal receipt: {result:?}"
    );
    let receipt = receipts.get(0).expect("terminal receipt");
    assert!(
        !receipt.is_allowed(),
        "failed finalization cannot allow delivery"
    );
    let response = result.expect("a healthy store must return the signed fault response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(response.receipt.id, receipt.id);
    assert_eq!(
        response.receipt.metadata.as_ref().and_then(|value| {
            value
                .pointer("/chio_runtime/identity_disposition")
                .and_then(serde_json::Value::as_str)
        }),
        Some("terminal")
    );
}

#[test]
fn malformed_post_invocation_envelope_has_one_terminal_receipt() {
    assert_failed_finalization_is_receipted(serde_json::Value::Null);
}

#[test]
fn missing_redacted_stream_chunks_has_one_terminal_receipt() {
    assert_failed_finalization_is_receipted(serde_json::json!({
        "kind": "stream", "stream": {"complete": true}
    }));
}

#[test]
fn unsupported_redacted_output_kind_has_one_terminal_receipt() {
    assert_failed_finalization_is_receipted(serde_json::json!({"kind": "unsupported"}));
}

#[test]
fn successful_call_has_one_allow_receipt() {
    let (kernel, request, invocations) = fixture();
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("valid call");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Allow);
    let receipts = kernel.receipt_log();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts.get(0).expect("allow receipt").id,
        response.receipt.id
    );
}

#[test]
fn caller_cannot_supply_receipt_namespace_or_disposition() {
    for key in ["receipt_context", "chio_runtime"] {
        let (kernel, request, invocations) = fixture();
        let result = kernel.evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(serde_json::json!({key: {
                "request_namespace_digest": "caller-selected", "identity_disposition": "reusable"
            }})),
        );
        assert!(result.is_err(), "caller metadata key {key} must be refused");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(kernel.receipt_log().is_empty());
    }
}
