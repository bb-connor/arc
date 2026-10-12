use super::*;

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

fn expired_refusal(nested: bool) {
    let (kernel, mut request, invocations) = fixture();
    let now = current_unix_timestamp();
    let mut body = request.capability.body();
    body.issued_at = now.saturating_sub(10);
    body.expires_at = now.saturating_sub(1);
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair).unwrap();
    let metadata = Some(serde_json::json!({"client_note": "preserved"}));
    let response = if nested {
        let context = make_operation_context(
            &SessionId::new("identity-expired-parent"),
            "identity-parent-request",
            &request.agent_id,
        );
        kernel.evaluate_tool_call_with_nested_flow_client(
            &context,
            &request,
            &mut NoopNestedFlowClient,
            metadata,
        )
    } else {
        kernel.evaluate_tool_call_blocking_with_metadata(&request, metadata)
    }
    .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("expired")));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(response.receipt.verify_signature().unwrap());
    let metadata = response.receipt.metadata.as_ref().unwrap();
    assert_eq!(metadata["client_note"], "preserved");
    assert_eq!(
        metadata
            .pointer("/chio_runtime/identity_disposition")
            .and_then(serde_json::Value::as_str),
        Some("reusable"),
    );
}

#[test]
fn ordinary_pre_admission_refusal_signs_reusable_identity() {
    expired_refusal(false);
}

#[test]
fn nested_pre_admission_refusal_signs_reusable_identity() {
    expired_refusal(true);
}

#[test]
fn healthy_allow_remains_signed_and_executes_once() {
    let (kernel, request, invocations) = fixture();
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_signature().unwrap());
}
