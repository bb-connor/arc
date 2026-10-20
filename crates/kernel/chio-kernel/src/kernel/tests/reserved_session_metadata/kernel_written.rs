//! Caller metadata cannot pre-set a top-level key that only the kernel writes.
//! Each key is pinned with its exact refusal across every caller entry point.
use super::*;

fn refused<T>(result: Result<T, KernelError>, expected: &str) -> bool {
    matches!(result, Err(KernelError::InvalidReceiptMetadata(reason)) if reason == expected)
}

fn assert_no_effect(kernel: &ChioKernel, context: &OperationContext, invocations: &AtomicU64) {
    assert_untouched(kernel, context, invocations);
    assert!(kernel.receipt_log().is_empty(), "a receipt was signed");
}

/// Refuses `key` with exactly `expected` on the blocking, async, reserving,
/// session and nested (sync and async) caller paths, before any tool effect
/// and before any receipt is signed.
fn assert_refused_on_every_caller_path(key: &str, expected: &str) {
    let (kernel, request, context, invocations) = fixture();
    assert!(
        refused(
            kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(metadata(key))),
            expected
        ),
        "blocking {key}"
    );
    assert_no_effect(&kernel, &context, &invocations);

    let (kernel, request, context, invocations) = fixture();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    assert!(
        refused(
            runtime
                .block_on(kernel.evaluate_tool_call_with_metadata(&request, Some(metadata(key)))),
            expected
        ),
        "async {key}"
    );
    assert_no_effect(&kernel, &context, &invocations);

    let (kernel, request, context, invocations) = fixture();
    assert!(
        refused(
            kernel.authorize_tool_call_reserving_blocking_with_metadata(
                &request,
                Some(metadata(key))
            ),
            expected
        ),
        "reserving {key}"
    );
    assert_no_effect(&kernel, &context, &invocations);

    let (kernel, request, context, invocations) = fixture();
    assert!(
        refused(
            kernel.evaluate_session_operation(
                &context,
                &SessionOperation::ToolCall(Box::new(operation(&request, key))),
            ),
            expected
        ),
        "session {key}"
    );
    assert_no_effect(&kernel, &context, &invocations);

    let (kernel, request, context, invocations) = fixture();
    assert!(
        refused(
            kernel.evaluate_tool_call_operation_with_nested_flow_client(
                &context,
                &operation(&request, key),
                &mut NoopNestedFlowClient,
            ),
            expected
        ),
        "nested sync {key}"
    );
    assert_no_effect(&kernel, &context, &invocations);

    let (kernel, request, context, invocations) = fixture();
    assert!(
        refused(
            runtime.block_on(
                kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
                    &context,
                    &operation(&request, key),
                    &mut NoopNestedFlowClient,
                )
            ),
            expected
        ),
        "nested async {key}"
    );
    assert_no_effect(&kernel, &context, &invocations);
}

#[test]
fn caller_cannot_set_governed_transaction_diagnostics() {
    assert_refused_on_every_caller_path(
        "governed_transaction_diagnostics",
        "governed_transaction_diagnostics is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_model_metadata() {
    assert_refused_on_every_caller_path(
        "model_metadata",
        "model_metadata is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_channel() {
    assert_refused_on_every_caller_path(
        "channel",
        "channel is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_delivery_contract() {
    assert_refused_on_every_caller_path(
        "delivery_contract",
        "delivery_contract is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_finding_delivery() {
    assert_refused_on_every_caller_path(
        "finding_delivery",
        "finding_delivery is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_finding_recovery() {
    assert_refused_on_every_caller_path(
        "finding_recovery",
        "finding_recovery is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_finding_purchase_replay_snapshot() {
    assert_refused_on_every_caller_path(
        "finding_purchase_replay_snapshot",
        "finding_purchase_replay_snapshot is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_finding_recovery_replay_snapshot() {
    assert_refused_on_every_caller_path(
        "finding_recovery_replay_snapshot",
        "finding_recovery_replay_snapshot is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_finding_denial() {
    assert_refused_on_every_caller_path(
        "findingDenial",
        "findingDenial is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_stream() {
    assert_refused_on_every_caller_path("stream", "stream is reserved for kernel-derived receipts");
}

#[test]
fn caller_cannot_set_threshold_approval() {
    assert_refused_on_every_caller_path(
        "threshold_approval",
        "threshold_approval is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_memory_provenance() {
    assert_refused_on_every_caller_path(
        "memory_provenance",
        "memory_provenance is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_post_invocation() {
    assert_refused_on_every_caller_path(
        "post_invocation",
        "post_invocation is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_execution_nonce() {
    assert_refused_on_every_caller_path(
        "execution_nonce",
        "execution_nonce is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_chio_kernel() {
    assert_refused_on_every_caller_path(
        "chio_kernel",
        "chio_kernel is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_runtime_admission() {
    assert_refused_on_every_caller_path(
        "runtime_admission",
        "runtime_admission is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_active_response_terminal_evidence() {
    assert_refused_on_every_caller_path(
        "active_response_terminal_evidence",
        "active_response_terminal_evidence is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_chio_http_receipt_v1() {
    assert_refused_on_every_caller_path(
        "chio_http_receipt_v1",
        "chio_http_receipt_v1 is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_chio_receipt_signing_nonce() {
    assert_refused_on_every_caller_path(
        "chio_receipt_signing_nonce",
        "chio_receipt_signing_nonce is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_original_metadata() {
    assert_refused_on_every_caller_path(
        "original_metadata",
        "original_metadata is reserved for kernel-derived receipts",
    );
}

/// A refused forged HTTP receipt projection leaves nothing in the receipt log,
/// and the next call signs a receipt without the projection key, so receipt
/// readers and evidence export never see the forgery.
#[test]
fn forged_http_receipt_projection_never_reaches_the_receipt_log() {
    let (kernel, request, _context, invocations) = fixture();
    assert!(refused(
        kernel.evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(serde_json::json!({"chio_http_receipt_v1": {"source": "forged"}})),
        ),
        "chio_http_receipt_v1 is reserved for kernel-derived receipts"
    ));
    assert!(kernel.receipt_log().is_empty());
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("unforged call");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_http_receipt_v1"))
        .is_none());
}

/// The check covers top-level keys only: a kernel-written key name nested
/// under a caller object is caller data, reaches the signed receipt only under
/// that object, and never appears as a top-level block.
#[test]
fn kernel_written_key_names_nested_under_caller_objects_stay_nested() {
    let (kernel, request, _context, invocations) = fixture();
    let response = kernel
        .evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(serde_json::json!({"client": {
                "delivery_contract": {"result": "matched"},
                "finding_delivery": {"finding_id": "forged"},
                "stream": {"chunks_received": 0}
            }})),
        )
        .expect("nested caller metadata is caller data");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata");
    for key in ["delivery_contract", "finding_delivery", "stream"] {
        assert!(metadata.get(key).is_none(), "{key} surfaced at top level");
        assert!(
            metadata.pointer(&format!("/client/{key}")).is_some(),
            "{key} left its caller object"
        );
    }
}
