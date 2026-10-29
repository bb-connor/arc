//! Caller metadata cannot pre-set a top-level key that only a Chio signer
//! writes. Each key is pinned with its exact refusal across every caller entry
//! point.
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
fn caller_cannot_set_decision_model_witness() {
    assert_refused_on_every_caller_path(
        "decision_model_witness",
        "decision_model_witness is reserved for kernel-derived receipts",
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

#[test]
fn caller_cannot_set_finding_pool_mutation() {
    assert_refused_on_every_caller_path(
        "finding_pool_mutation",
        "finding_pool_mutation is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_session_report() {
    assert_refused_on_every_caller_path(
        "session_report",
        "session_report is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_prior_metadata() {
    assert_refused_on_every_caller_path(
        "prior_metadata",
        "prior_metadata is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_lineage_references() {
    assert_refused_on_every_caller_path(
        "lineageReferences",
        "lineageReferences is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_session_anchor() {
    assert_refused_on_every_caller_path(
        "session_anchor",
        "session_anchor is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_acp() {
    assert_refused_on_every_caller_path("acp", "acp is reserved for kernel-derived receipts");
}

#[test]
fn caller_cannot_set_otel() {
    assert_refused_on_every_caller_path("otel", "otel is reserved for kernel-derived receipts");
}

#[test]
fn caller_cannot_set_parent_receipt_ids() {
    assert_refused_on_every_caller_path(
        "parent_receipt_ids",
        "parent_receipt_ids is reserved for kernel-derived receipts",
    );
}

#[test]
fn caller_cannot_set_chio_kernel_receipt_id() {
    assert_refused_on_every_caller_path(
        "chio_kernel_receipt_id",
        "chio_kernel_receipt_id is reserved for kernel-derived receipts",
    );
}

/// Caller-origin keys stay admissible as caller metadata; only `ChioInternal`
/// keys are reserved.
#[test]
fn caller_origin_keys_are_not_reserved() {
    use chio_core::receipt::metadata::{MetadataKeyOrigin, RECEIPT_METADATA_KEYS};
    for spec in RECEIPT_METADATA_KEYS {
        let metadata = serde_json::json!({ spec.key: {"forged": true} });
        let reserved = crate::kernel::reserved_receipt_metadata_key(Some(&metadata));
        match spec.origin {
            MetadataKeyOrigin::ChioInternal => assert_eq!(reserved, Some(spec.key)),
            MetadataKeyOrigin::CallerOrHook => assert_eq!(reserved, None, "{}", spec.key),
        }
    }
}

/// Every key the kernel crate names for a block it writes is in the reserved
/// set derived from the registry.
#[test]
fn kernel_written_metadata_key_consts_are_reserved() {
    for key in [
        crate::admission_operation::ADMISSION_RECEIPT_METADATA_KEY,
        crate::kernel::MANIFEST_SECURITY_METADATA_KEY,
        crate::kernel::PROTOCOL_ADMISSION_METADATA_KEY,
        crate::kernel::BUDGET_AUTHORITY_METADATA_KEY,
        crate::kernel::BUDGET_DENIAL_AUTHORITY_METADATA_KEY,
        crate::kernel::FINANCIAL_METADATA_KEY,
        crate::kernel::GOVERNED_TRANSACTION_METADATA_KEY,
        crate::kernel::CALLER_DELIVERY_METADATA_KEY,
        crate::kernel::RUNTIME_ADMISSION_METADATA_KEY,
        crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY,
        crate::finding_recovery::FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY,
        crate::finding_denial::FINDING_DENIAL_METADATA_KEY,
    ] {
        assert!(
            chio_core::receipt::metadata::reserved_receipt_metadata_keys()
                .any(|reserved| reserved == key),
            "{key}"
        );
    }
}

/// Pins the reserved set the registry derives exactly, so a key whose origin
/// changes fails here, and pins each key's exact refusal reason.
#[test]
fn reserved_receipt_metadata_keys_are_pinned_exactly() {
    let reserved: Vec<&str> =
        chio_core::receipt::metadata::reserved_receipt_metadata_keys().collect();
    assert_eq!(
        reserved,
        [
            "admission_operation",
            "attribution",
            "chio_manifest_security_v1",
            "protocol_admission",
            "budget_authority",
            "budget_denial_authority",
            "financial",
            "governed_transaction",
            "caller_delivery",
            "protocol_refusal",
            "chio_runtime",
            "session_anchor",
            "receipt_context",
            "governed_transaction_diagnostics",
            "model_metadata",
            "channel",
            "delivery_contract",
            "finding_delivery",
            "finding_recovery",
            "finding_purchase_replay_snapshot",
            "finding_recovery_replay_snapshot",
            "decision_model_witness",
            "findingDenial",
            "stream",
            "threshold_approval",
            "memory_provenance",
            "post_invocation",
            "execution_nonce",
            "chio_kernel",
            "runtime_admission",
            "active_response_terminal_evidence",
            "chio_http_receipt_v1",
            "chio_receipt_signing_nonce",
            "original_metadata",
            "finding_pool_mutation",
            "session_report",
            "prior_metadata",
            "lineageReferences",
            "chio_http_status_scope",
            "chio_decision_receipt_id",
            "chio_kernel_receipt_id",
            "otel",
            "correlation",
            "keyEnterpriseReceipt",
            "active_defense_evidence_id",
            "occurred_at_unix_ms",
            "response_simulation_evidence_id",
            "scimLifecycle",
            "mercury",
            "authorizationContext",
            "guardOutcome",
            "deniedAccessRecord",
            "policySnapshot",
            "acp",
            "agent_web_receipt_ref",
            "parent_receipt_ids",
            "batch_witness",
        ]
    );
    for key in reserved {
        let purpose = match key {
            "chio_manifest_security_v1" => "registry-validated kernel entrypoints",
            "protocol_admission" => "kernel-derived admission receipts",
            "budget_authority" | "budget_denial_authority" => "kernel-derived budget receipts",
            "financial" | "governed_transaction" => "kernel-derived economic receipts",
            "chio_runtime" => "kernel-derived runtime admission reservations",
            _ => "kernel-derived receipts",
        };
        let metadata = serde_json::json!({ key: {"forged": true} });
        assert!(
            refused(
                crate::kernel::validate_caller_receipt_metadata(Some(&metadata)),
                &format!("{key} is reserved for {purpose}")
            ),
            "{key}"
        );
    }
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
