use super::*;
use crate::kernel::tests::evidence_recovery::wait_for_post_effect_evidence;

#[test]
fn nested_flow_drop_post_dispatch_records_cancellation_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ParkingServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&started),
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-dropped",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
        assert!(
            raced.is_err(),
            "parked nested dispatch must be dropped by the timeout"
        );
    });

    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "nested dispatch must have been entered before the drop"
    );
    wait_for_post_effect_evidence(&kernel);
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "nested-flow drop must record exactly one receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("nested drop receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the nested drop receipt".into());
    };
    assert_eq!(reason, "post-effect finalization failed; output withheld");
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_runtime/post_effect_fault/code")),
        Some(&serde_json::json!("CHIO-KERNEL-POST-EFFECT-DROP")),
    );
    Ok(())
}

// Normal nested-flow exit commits each child once before its parent terminal.
#[test]
fn nested_flow_normal_path_records_child_receipt_exactly_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        false,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-normal",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-normal",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _response = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        1,
        "the nested child op must have run once"
    );
    wait_for_post_effect_evidence(&kernel);
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the normal nested-flow exit records exactly one parent receipt"
    );
    assert!(
        !receipt_log
            .get(0)
            .ok_or_else(|| std::io::Error::other("parent receipt missing"))?
            .is_cancelled(),
        "the normal-path parent receipt must not be a cancellation"
    );
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the buffered child receipt must be recorded exactly once on the normal path"
    );
    Ok(())
}

// An unknown child append with no authoritative readback keeps both the child
// and parent evidence owned, and refuses subsequent dispatch.
#[test]
fn nested_flow_unknown_child_append_retains_the_parent_obligation(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ChildAppendTimeoutStore))?;
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        false,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-child-timeout",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-child-timeout",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    assert!(
        child_ops.load(Ordering::SeqCst) >= 1,
        "the nested child op must have run before the child-receipt append"
    );
    assert!(matches!(
        result,
        Err(KernelError::ReceiptPersistence(ReceiptStoreError::Timeout {
            operation,
            timeout_ms: 0,
        })) if operation == "append_child_receipt"
    ));
    assert!(matches!(
        kernel.ensure_post_effect_evidence_latch_clear(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    assert!(kernel.receipt_log().is_empty());
    assert!(kernel.child_receipt_log().is_empty());
    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&request),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    assert_eq!(child_ops.load(Ordering::SeqCst), 1);
    Ok(())
}

// A completed writer barrier and retained-history absence permit a retry of
// the same signed child. Recovery then commits one parent cancellation.
#[test]
fn nested_flow_transient_child_append_timeout_preserves_child_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let child_appends = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ChildAppendFailsOnceStore {
        child_appends: std::sync::Arc::clone(&child_appends),
        receipts: Mutex::new(Vec::new()),
    }))?;
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        false,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-child-retry",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-child-retry",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        1,
        "the nested child op must have run once before the child-receipt append"
    );
    assert!(
        result.is_err(),
        "the first child-receipt append timeout must surface as an error"
    );
    wait_for_post_effect_evidence(&kernel);
    assert_eq!(
        child_appends.load(Ordering::SeqCst),
        2,
        "authoritative absence after the writer barrier permits one retry"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the abort cleanup records exactly one signed cancellation receipt"
    );
    assert!(
        receipt_log
            .get(0)
            .ok_or_else(|| std::io::Error::other("terminal receipt missing"))?
            .is_cancelled(),
        "the terminal receipt must be a signed cancellation"
    );
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the buffered child receipt must be preserved and flushed on the drop-path retry, not lost"
    );
    Ok(())
}

// A failed first child remains at the queue front until authoritative absence
// permits retry. Both children must eventually persist, with distinct identities.
#[test]
fn nested_flow_drop_path_preserves_child_receipts_after_a_first_append_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let child_appends = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ChildAppendFailsOnceStore {
        child_appends: std::sync::Arc::clone(&child_appends),
        receipts: Mutex::new(Vec::new()),
    }))?;
    kernel.register_tool_server(Box::new(TwoChildOpParkingServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-drop-multi",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-drop-multi",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
        assert!(
            raced.is_err(),
            "parked nested dispatch must be dropped by the timeout"
        );
    });

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        2,
        "both nested child ops must have run before the drop"
    );
    wait_for_post_effect_evidence(&kernel);
    assert_eq!(child_appends.load(Ordering::SeqCst), 3);
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        2,
        "both children survive the first failure"
    );
    let child_ids: Vec<_> = child_receipt_log
        .iter()
        .map(|receipt| &receipt.id)
        .collect();
    assert_ne!(child_ids[0], child_ids[1]);
    assert_eq!(kernel.receipt_log().len(), 1);
    Ok(())
}

// Post-dispatch parent drop: the already-signed buffered child receipt must be
// flushed onto the append-only log alongside the parent cancellation receipt.
// Without the drop-path flush the child receipt is discarded with the dropped
// future, violating receipt-completeness for nested child operations.
#[test]
fn nested_flow_drop_post_dispatch_flushes_buffered_child_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        true,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-child-dropped",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-child-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
        assert!(
            raced.is_err(),
            "parked nested dispatch must be dropped by the timeout"
        );
    });

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        1,
        "the nested child op must have run before the drop"
    );
    wait_for_post_effect_evidence(&kernel);
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the parent cancellation receipt must be recorded on drop"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("parent cancellation receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the nested drop receipt".into());
    };
    assert_eq!(reason, "post-effect finalization failed; output withheld");
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_runtime/post_effect_fault/code")),
        Some(&serde_json::json!("CHIO-KERNEL-POST-EFFECT-DROP")),
    );
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the buffered signed child receipt must be flushed on post-dispatch drop, not discarded"
    );
    Ok(())
}
