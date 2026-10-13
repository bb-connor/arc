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
        assert!(
            matches!(
                &result,
                Err(KernelError::InvalidReceiptMetadata(message))
                    if message.starts_with(&format!("{key} is reserved for "))
            ),
            "caller metadata key {key} must be refused: {result:?}"
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(kernel.receipt_log().is_empty());
    }
}
