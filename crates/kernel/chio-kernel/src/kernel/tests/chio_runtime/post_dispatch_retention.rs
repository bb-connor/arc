use super::*;

#[test]
fn chio_runtime_admission_does_not_release_destructive_lease_after_dispatch_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-dispatch-error",
        admission_id: "adm-dispatch-error",
        lease_id: "lease-dispatch-error",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-dispatch-error",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "destructive runtime leases must remain consumed after tool dispatch starts"
    );
    assert_eq!(
        response.reason.as_deref(),
        Some("internal error: destructive side effect committed before transport failure")
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-dispatch-error"
    );
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-dispatch-error"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_non_durable_url_elicitation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-url-elicitation",
        admission_id: "adm-url-elicitation",
        lease_id: "lease-url-elicitation",
        continuation_id: Some("continuation-url-elicitation"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-url-elicitation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("URL elicitation must surface to the caller");

    assert!(matches!(error, KernelError::UrlElicitationsRequired { .. }));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a tool-controlled URL elicitation cannot prove that dispatch had no side effects"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("URL elicitation ambiguity receipt missing"))?;
    assert!(receipt.is_cancelled());
    assert!(receipt.verify_signature()?);
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_ambiguous_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CancellationAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-cancelled",
        admission_id: "adm-cancelled",
        lease_id: "lease-cancelled",
        continuation_id: Some("continuation-cancelled"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-cancelled",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "runtime reservations must stay consumed when cancellation does not prove absence of side effects"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_ambiguous_incomplete(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-incomplete",
        admission_id: "adm-incomplete",
        lease_id: "lease-incomplete",
        continuation_id: Some("continuation-incomplete"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-incomplete",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "runtime reservations must stay consumed when incompletion does not prove absence of side effects"
    );
    Ok(())
}

#[test]
fn chio_post_admission_drop_guard_retains_non_monetary_runtime_reservations(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-dropped",
        admission_id: "adm-dropped",
        lease_id: "lease-dropped",
        continuation_id: Some("continuation-dropped"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-dropped",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-dropped",
            "reserved_treaty_continuation_id": "continuation-dropped",
            "failure_code": null
        }
    });

    let mutation = PreExecutionBudgetMutation::None;
    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    );
    guard.mark_dispatch_started();
    drop(guard);

    assert_eq!(admission_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a post-dispatch drop cannot prove absence of side effects, so reservations stay consumed"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a post-dispatch drop must record exactly one cancellation receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("drop receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the drop receipt".into());
    };
    assert_eq!(reason, "tool evaluation future dropped after admission");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_non_monetary_post_dispatch_records_cancellation_receipt(
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
    let request = make_request_with_arguments(
        "req-chio-runtime-non-monetary-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .map_err(|_| std::io::Error::other("parking tool server was never invoked"))?;
    eval.abort();
    assert!(eval.await.is_err(), "aborted evaluation must not complete");

    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "dropped non-monetary post-admission future must record exactly one receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("cancellation receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the drop receipt".into());
    };
    assert_eq!(reason, "tool evaluation future dropped after admission");
    assert!(
        receipt.verify_signature()?,
        "drop receipt signature must verify"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_post_dispatch_retains_and_marks_reservations(
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
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-drop-retained",
        admission_id: "adm-drop-retained",
        lease_id: "lease-drop-retained",
        continuation_id: Some("continuation-drop-retained"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-drop-retained",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .map_err(|_| std::io::Error::other("parking tool server was never invoked"))?;
    eval.abort();
    assert!(eval.await.is_err(), "aborted evaluation must not complete");

    // Retention: the mock hook's release_reserved was never called, so the
    // consumed lease stays consumed (a retry would be rejected with
    // destructive_lease_replay by the real store, per
    // chio-runtime-core/src/store/memory.rs:136-151).
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a post-dispatch drop must retain runtime-admission reservations"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("drop receipt missing"))?;
    assert!(receipt.is_cancelled());
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("drop receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-drop-retained"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-drop-retained"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-drop-retained"
    );
    assert!(
        metadata["chio_runtime"]
            .get("retained_swarm_continuation_id")
            .is_none(),
        "no swarm continuation was reserved by this fixture, so the retained \
         marker for it must be absent"
    );
    Ok(())
}

#[test]
fn request_cancelled_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CancellationAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-cancel-marked",
        admission_id: "adm-cancel-marked",
        lease_id: "lease-cancel-marked",
        continuation_id: Some("continuation-cancel-marked"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-cancel-marked",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "ambiguous cancellation must retain reservations"
    );
    assert!(response.receipt.is_cancelled());
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("cancel receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-cancel-marked"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-cancel-marked"
    );
    Ok(())
}

#[test]
fn request_incomplete_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-incomplete-marked",
        admission_id: "adm-incomplete-marked",
        lease_id: "lease-incomplete-marked",
        continuation_id: Some("continuation-incomplete-marked"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-incomplete-marked",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "ambiguous incompletion must retain reservations"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-incomplete-marked"
    );
    Ok(())
}

#[test]
fn incomplete_stream_output_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>>
{
    // Dispatch succeeds but returns Ok(ToolServerStreamResult::Incomplete)
    // (e.g. stream-limit truncation). This is finalized via
    // finalize_budgeted_tool_output_with_cost_and_metadata / the shared
    // finalize path, NOT the RequestIncomplete error arm. The
    // runtime-admission lease is still consumed after the side effect, so
    // the incomplete receipt must carry the retained marker so the burned
    // lease is auditable and recoverable from the signed receipt alone.
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteStreamAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-incomplete-stream-marked",
        admission_id: "adm-incomplete-stream-marked",
        lease_id: "lease-incomplete-stream-marked",
        continuation_id: Some("continuation-incomplete-stream-marked"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-incomplete-stream-marked",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "an incomplete stream after a side effect must retain reservations"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("incomplete-stream receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-incomplete-stream-marked"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-incomplete-stream-marked"
    );
    Ok(())
}

#[test]
fn post_invocation_block_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>> {
    // A runtime-admitted call dispatches successfully (a destructive side
    // effect commits) and returns a value, but a POST-invocation output guard
    // blocks the returned value AFTER dispatch. Because the tool already ran,
    // the runtime-admission lease is retained (not released), so the deny
    // receipt must carry the retained marker + reserved ids to keep the burned
    // lease auditable and recoverable from the signed receipt alone, matching
    // the incomplete-stream and RequestIncomplete arms.
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SucceedingAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    kernel.add_post_invocation_hook(Box::new(BlockingPostInvocationHook));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-post-invocation-block",
        admission_id: "adm-post-invocation-block",
        lease_id: "lease-post-invocation-block",
        continuation_id: Some("continuation-post-invocation-block"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-post-invocation-block",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        side_effects.load(Ordering::SeqCst),
        1,
        "tool must have dispatched (side effect committed) before the post-invocation block"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a post-invocation block after a side effect must retain reservations"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("post-invocation block receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-post-invocation-block"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-post-invocation-block"
    );
    Ok(())
}

#[test]
fn connector_tool_not_registered_after_side_effect_retains_admission(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-tool-not-registered",
        admission_id: "adm-tool-not-registered",
        lease_id: "lease-tool-not-registered",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-tool-not-registered",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("destructive_update")));
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "connector errors after tool entry must retain reservations"
    );
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny receipt metadata missing"))?;
    let runtime = metadata["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block missing"))?;
    assert_eq!(runtime["reservations_retained_fail_closed"], true);
    assert_eq!(
        runtime["retained_destructive_lease_id"],
        "lease-tool-not-registered"
    );
    Ok(())
}

#[test]
fn dispatch_not_registered_retains_full_budget_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-dispatch-not-registered-full-budget-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);

    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "post-entry connector errors must retain the invocation increment"
    );
    Ok(())
}

#[test]
fn dispatch_not_registered_retains_full_budget_state_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-dispatch-not-registered-full-budget-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-dispatch-not-registered-full-budget-nested",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;
    assert_eq!(response.verdict, Verdict::Deny);

    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "nested post-entry connector errors must retain the invocation increment"
    );
    Ok(())
}

#[test]
fn non_durable_url_elicitation_retains_full_budget_state() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-url-elicitation-full-budget-async",
        admission_id: "adm-url-elicitation-full-budget-async",
        lease_id: "lease-url-elicitation-full-budget-async",
        continuation_id: Some("continuation-url-elicitation-full-budget-async"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-elicitation-full-budget-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "URL elicitation must surface as an error to the caller"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );

    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "a tool-controlled URL elicitation must retain the invocation slot fail-closed"
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn non_durable_url_elicitation_retains_full_budget_state_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-url-elicitation-full-budget-nested",
        admission_id: "adm-url-elicitation-full-budget-nested",
        lease_id: "lease-url-elicitation-full-budget-nested",
        continuation_id: Some("continuation-url-elicitation-full-budget-nested"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-elicitation-full-budget-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-full-budget-nested",
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
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the nested-flow URL elicitation must surface as an error to the caller"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );

    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "a nested tool-controlled URL elicitation must retain the invocation slot fail-closed"
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn retained_marker_requires_a_real_reservation() -> Result<(), Box<dyn std::error::Error>> {
    // A `chio_runtime` block that merely carries a route / observe-only key with NO
    // reserved lease id must NOT be marked `reservations_retained_fail_closed`.
    // There is nothing to burn, so the marker would send an operator hunting for a
    // lease that never existed.
    let kernel = make_kernel(make_config());

    // (a) chio_runtime present, but no reserved_* id: NOT marked retained; the
    // metadata is returned unchanged.
    let route_only = serde_json::json!({
        "chio_runtime": { "admission_id": "adm-observe-only", "accepted": true }
    });
    let marked = kernel
        .mark_runtime_admission_reservations_retained_fail_closed(Some(route_only))
        .ok_or_else(|| std::io::Error::other("metadata must be returned"))?;
    let runtime = marked["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block must be preserved"))?;
    assert!(
        !runtime.contains_key("reservations_retained_fail_closed"),
        "metadata with no real reservation must not be marked retained: {runtime:?}"
    );
    assert!(!runtime.contains_key("retained_destructive_lease_id"));

    // (b) an empty reserved id is not a real reservation either.
    let empty_id = serde_json::json!({
        "chio_runtime": { "reserved_destructive_lease_id": "" }
    });
    let marked_empty = kernel
        .mark_runtime_admission_reservations_retained_fail_closed(Some(empty_id))
        .ok_or_else(|| std::io::Error::other("metadata must be returned"))?;
    assert!(
        !marked_empty["chio_runtime"]
            .as_object()
            .is_some_and(|runtime| runtime.contains_key("reservations_retained_fail_closed")),
        "an empty reserved id is not a real reservation"
    );

    // (c) a real, non-empty reserved lease id IS marked retained and copied so
    // an operator can burn/recover the stuck lease from the signed receipt.
    let real = serde_json::json!({
        "chio_runtime": { "reserved_destructive_lease_id": "lease-real-42" }
    });
    let marked_real = kernel
        .mark_runtime_admission_reservations_retained_fail_closed(Some(real))
        .ok_or_else(|| std::io::Error::other("metadata must be returned"))?;
    let runtime_real = marked_real["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block must be preserved"))?;
    assert_eq!(
        runtime_real["reservations_retained_fail_closed"],
        serde_json::Value::Bool(true),
        "a real reserved lease must be marked retained"
    );
    assert_eq!(
        runtime_real["retained_destructive_lease_id"], "lease-real-42",
        "the stuck lease id must be copied for operator recovery"
    );
    Ok(())
}
