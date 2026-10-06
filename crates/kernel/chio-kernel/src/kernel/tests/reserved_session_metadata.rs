//! Untrusted metadata must reject before request ownership or runtime release.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const RESERVED_KEYS: [&str; 9] = [
    "chio_manifest_security_v1",
    "protocol_admission",
    "budget_authority",
    "budget_denial_authority",
    "financial",
    "governed_transaction",
    "caller_delivery",
    "protocol_refusal",
    "chio_runtime",
];

fn fixture() -> (
    ChioKernel,
    ToolCallRequest,
    OperationContext,
    StdArc<AtomicU64>,
) {
    let mut kernel = make_kernel(make_config());
    let invocations = StdArc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "metadata-server",
        vec!["read"],
        invocations.clone(),
    )));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("metadata-server", "read")]),
        300,
    );
    let request = make_request("reserved-metadata", &capability, "read", "metadata-server");
    let session = kernel
        .open_session(agent.public_key().to_hex(), vec![capability])
        .expect("open metadata session");
    kernel
        .activate_session(&session)
        .expect("activate metadata session");
    let context = make_operation_context(&session, &request.request_id, &request.agent_id);
    (kernel, request, context, invocations)
}

fn metadata(key: &str) -> serde_json::Value {
    serde_json::json!({key: {
        "admission_id": "foreign-admission",
        "reserved_destructive_lease_id": "foreign-single-use-lease"
    }})
}

fn operation(request: &ToolCallRequest, key: &str) -> ToolCallOperation {
    serde_json::from_value(serde_json::json!({
        "capability": request.capability,
        "server_id": request.server_id,
        "tool_name": request.tool_name,
        "arguments": request.arguments,
        "extra_metadata": metadata(key)
    }))
    .expect("metadata operation")
}

fn assert_rejected<T>(result: Result<T, KernelError>, key: &str) {
    assert!(
        matches!(result, Err(KernelError::InvalidReceiptMetadata(ref reason)) if reason.contains(key)),
        "{key} did not reject as reserved receipt metadata"
    );
}

fn assert_untouched(kernel: &ChioKernel, context: &OperationContext, invocations: &AtomicU64) {
    let session = kernel
        .session(&context.session_id)
        .expect("metadata session");
    assert!(session.inflight().is_empty());
    assert!(session.terminal().get(&context.request_id).is_none());
    assert!(session.request_lineage(&context.request_id).is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn session_rejects_reserved_metadata_before_claiming_request() -> TestResult {
    let (kernel, request, context, invocations) = fixture();
    for key in RESERVED_KEYS {
        assert_rejected(
            kernel.evaluate_session_operation(
                &context,
                &SessionOperation::ToolCall(Box::new(operation(&request, key))),
            ),
            key,
        );
        assert_untouched(&kernel, &context, &invocations);
    }
    Ok(())
}

#[test]
fn nested_sync_rejects_reserved_metadata_before_claiming_request() -> TestResult {
    let (kernel, request, context, invocations) = fixture();
    for key in RESERVED_KEYS {
        assert_rejected(
            kernel.evaluate_tool_call_operation_with_nested_flow_client(
                &context,
                &operation(&request, key),
                &mut NoopNestedFlowClient,
            ),
            key,
        );
        assert_untouched(&kernel, &context, &invocations);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn nested_async_rejects_reserved_metadata_before_claiming_request() -> TestResult {
    let (kernel, request, context, invocations) = fixture();
    for key in RESERVED_KEYS {
        assert_rejected(
            kernel
                .evaluate_tool_call_operation_with_nested_flow_client_async(
                    &context,
                    &operation(&request, key),
                    &mut NoopNestedFlowClient,
                )
                .await,
            key,
        );
        assert_untouched(&kernel, &context, &invocations);
    }
    Ok(())
}

#[test]
fn reserving_blocking_rejects_reserved_metadata() -> TestResult {
    let (kernel, request, context, invocations) = fixture();
    for key in RESERVED_KEYS {
        assert_rejected(
            kernel.authorize_tool_call_reserving_blocking_with_metadata(
                &request,
                Some(metadata(key)),
            ),
            key,
        );
        assert_untouched(&kernel, &context, &invocations);
    }
    Ok(())
}

#[test]
fn blocking_rejects_runtime_release_metadata() -> TestResult {
    let (kernel, request, context, invocations) = fixture();
    assert_rejected(
        kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(metadata("chio_runtime"))),
        "chio_runtime",
    );
    assert_untouched(&kernel, &context, &invocations);
    Ok(())
}
