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
fn connector_tool_not_registered_retains_reservations_and_marks_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
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
        "a connector error variant cannot prove that no side effect occurred"
    );
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
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
fn connector_tool_not_registered_retains_invocation_top_level(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "connector-not-registered-top-level");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
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
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert!(!kernel.budget_store.try_increment(&cap.id, 0, Some(1))?);
    Ok(())
}

#[test]
fn connector_tool_not_registered_retains_invocation_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "connector-not-registered-nested");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
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
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert!(!kernel.budget_store.try_increment(&cap.id, 0, Some(1))?);
    Ok(())
}

#[test]
fn connector_url_elicitation_retains_invocation_top_level() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "connector-url-elicitation-top-level");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
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

    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert!(!kernel.budget_store.try_increment(&cap.id, 0, Some(1))?);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    assert!(receipt_log.get(0).unwrap().is_incomplete());
    Ok(())
}

#[test]
fn connector_url_elicitation_retains_invocation_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "connector-url-elicitation-nested");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
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

    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert!(!kernel.budget_store.try_increment(&cap.id, 0, Some(1))?);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    assert!(receipt_log.get(0).unwrap().is_incomplete());
    Ok(())
}

fn assert_monetary_url_elicitation_release_projection(
    nested: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = if nested {
        "req-monetary-url-release-nested"
    } else {
        "req-monetary-url-release-top"
    };
    let mut kernel = make_kernel(make_monetary_config());
    install_runtime_bounded_budget_authorities(&mut kernel, request_id);
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: request_id,
        admission_id: "adm-monetary-url-release",
        lease_id: "lease-monetary-url-release",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let request = make_request_with_arguments(
        request_id,
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let result = if nested {
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
        kernel.activate_session(&session_id)?;
        let context =
            make_operation_context(&session_id, request_id, &agent_kp.public_key().to_hex());
        kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    &request,
                    &mut client,
                    None,
                )
                .await
        })
    } else {
        kernel.evaluate_tool_call_blocking(&request)
    };

    assert!(matches!(
        result,
        Err(KernelError::UrlElicitationsRequired { .. })
    ));
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_incomplete());
    let metadata = receipt.metadata.as_ref().unwrap();
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    let terminal = &metadata["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
    Ok(())
}

#[test]
fn monetary_url_elicitation_success_projects_release_top_level(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_monetary_url_elicitation_release_projection(false)
}

#[test]
fn monetary_url_elicitation_success_projects_release_nested(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_monetary_url_elicitation_release_projection(true)
}

/// Sibling-sum delegation fixture whose child capabilities target a tool server
/// that returns `UrlElicitationsRequired` before any side effect. Parent share
/// is 5000 bps and each child claims 4000 bps, so child_a alone fits but
/// child_a + child_b oversubscribes the parent. Mirrors
/// `make_sibling_sum_invocation_fixture` but swaps the tool server so the
/// evaluation reaches dispatch and surfaces the URL-elicitation error.
fn make_sibling_sum_url_fixture(prefix: &str) -> SiblingSumInvocationFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_monetary_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "url-srv",
        vec!["compute"],
        stream_attempts,
    )));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_grant("url-srv", "compute");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_grant("url-srv", "compute")]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    trust_delegated_leaf_signer_for_scope(&mut kernel, &parent_kp, &parent_scope);

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: &child_a_id,
        share_bps: 4_000,
    });
    let child_b_id = format!("cap-{prefix}-child-b");
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: &child_b_id,
        share_bps: 4_000,
    });

    SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

#[test]
fn url_elicitation_retained_evaluation_holder_blocks_sibling_top_level(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp: _child_a_kp,
        path: _path,
        ..
    } = make_sibling_sum_url_fixture("chio-runtime-url-idempotent-readmit");

    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission must acquire child_a's lease");

    let request = make_request_with_arguments(
        "req-url-idempotent-readmit-async",
        &child_a,
        "compute",
        "url-srv",
        serde_json::json!({}),
    );
    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the delegated child must reach dispatch and surface UrlElicitationsRequired: {result:?}"
    );

    kernel
        .release_admitted_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    let readmit_b = kernel.admit_capability_budget(&child_b);
    assert!(
        readmit_b.is_err(),
        "after releasing the explicit first holder, the connector-error evaluation's retained holder must still block child_b: {readmit_b:?}"
    );
    Ok(())
}

#[test]
fn url_elicitation_retained_evaluation_holder_blocks_sibling_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        path: _path,
        ..
    } = make_sibling_sum_url_fixture("chio-runtime-url-idempotent-readmit-nested");

    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission must acquire child_a's lease");

    let session_id =
        kernel.open_session(child_a_kp.public_key().to_hex(), vec![child_a.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-idempotent-readmit-nested",
        &child_a_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-idempotent-readmit-nested",
        &child_a,
        "compute",
        "url-srv",
        serde_json::json!({}),
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
        "the nested delegated child must surface UrlElicitationsRequired: {result:?}"
    );

    kernel
        .release_admitted_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    let readmit_b = kernel.admit_capability_budget(&child_b);
    assert!(
        readmit_b.is_err(),
        "after releasing the explicit first holder, the nested connector-error evaluation's retained holder must still block child_b: {readmit_b:?}"
    );
    Ok(())
}

#[test]
fn url_elicitation_retains_runtime_reservations_and_invocation_top_level(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "url-runtime-reservations-top-level");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-url-elicitation-release-failure-async",
        admission_id: "adm-url-elicitation-release-failure",
        lease_id: "lease-url-elicitation-release-failure",
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
        "req-url-elicitation-release-failure-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "a runtime-release failure must not replace the elicitation with an internal cleanup error: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "post-dispatch URL elicitation retains runtime reservations"
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert!(!kernel.budget_store.try_increment(&cap.id, 0, Some(1))?);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_incomplete());
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    Ok(())
}

#[test]
fn url_elicitation_retains_runtime_reservations_and_invocation_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "url-runtime-reservations-nested");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-url-elicitation-release-failure-nested",
        admission_id: "adm-url-elicitation-release-failure-nested",
        lease_id: "lease-url-elicitation-release-failure-nested",
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
        "req-url-elicitation-release-failure-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-release-failure-nested",
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
        "the nested runtime-release failure must not mask the elicitation error: {result:?}"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "nested post-dispatch URL elicitation retains runtime reservations"
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0)?.unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert!(!kernel.budget_store.try_increment(&cap.id, 0, Some(1))?);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_incomplete());
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    Ok(())
}

/// Assert that a failed post-dispatch budget or payment release recorded a
/// signed incomplete receipt naming the cleanup step and stuck hold.
fn assert_url_elicitation_budget_cleanup_fault_recorded(
    kernel: &ChioKernel,
    step: &str,
    hold_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt_log = kernel.receipt_log();
    let found = receipt_log.receipts().iter().any(|receipt| {
        receipt.is_incomplete()
            && receipt.metadata.as_ref().is_some_and(|metadata| {
                metadata["chio_runtime"]["post_dispatch_cleanup_failed"] == true
                    && metadata["budget_authority"]["terminal"].is_null()
                    && receipt
                        .financial_budget_authority_metadata()
                        .is_some_and(|authority| authority.terminal.is_none())
                    && metadata["chio_runtime"]["post_dispatch_cleanup_faults"]
                        .as_array()
                        .is_some_and(|faults| {
                            faults.iter().any(|fault| {
                                fault["step"] == step
                                    && fault["reason"].as_str().is_some_and(|reason| {
                                        reason.contains("[REDACTED-API-KEY]")
                                            && !reason.contains("sk_live_")
                                    })
                                    && fault["attempted_release_event_id"]
                                        .as_str()
                                        .is_some_and(|event_id| event_id.ends_with(":release"))
                                    && fault["hold_ids"]
                                        .as_array()
                                        .is_some_and(|ids| ids.iter().any(|id| id == hold_id))
                            })
                        })
            })
    });
    assert!(
        found,
        "a failed URL-elicitation post-dispatch release must record a signed fault receipt naming step `{step}` and the stuck hold `{hold_id}`"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_cleanup_fault_receipt_includes_monetary_hold_id(
) -> Result<(), Box<dyn std::error::Error>> {
    // When a pre-dispatch drop hits a monetary cleanup failure, the fault entry
    // must name the budget hold id it was unwinding so an operator can locate the
    // possibly-stuck hold from the fault receipt alone. The fabricated charge has no
    // matching open hold in the store, so the monetary reversal fails and records a
    // fault.
    let kernel = make_kernel(make_config());

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-monetary-cleanup-fault-hold-id",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    // Charge WITHOUT authorizing the matching hold: the monetary reversal fails
    // and records a monetary_unwind fault (no mark_dispatch_started, so this is
    // the pre-dispatch drop branch).
    let mutation =
        PreExecutionBudgetMutation::Charge(Box::new(make_fabricated_drop_charge()));
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a failed monetary pre-dispatch cleanup must record exactly one fault receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("monetary cleanup fault receipt missing"))?;
    let receipt_metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("fault receipt metadata missing"))?;
    let faults = receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("fault list missing"))?;
    let monetary_fault = faults
        .iter()
        .find(|fault| fault["step"] == "monetary_unwind")
        .ok_or_else(|| std::io::Error::other("monetary_unwind fault entry missing"))?;
    let hold_ids = monetary_fault["hold_ids"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("monetary_unwind fault must carry hold_ids"))?;
    assert!(
        hold_ids.iter().any(|id| id == "hold-drop-guard-tests"),
        "the monetary_unwind fault must name the budget hold id: {hold_ids:?}"
    );
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

/// A [`PaymentAdapter`] that authorizes cleanly but FAILS on release, so a
/// monetary UrlElicitationsRequired cleanup exercises the payment-release
/// failure arm of the post-dispatch release helper. The authorization id is
/// deterministic so a test can assert it lands in the recorded fault's `hold_ids`.
struct FailingReleasePaymentAdapter;

impl FailingReleasePaymentAdapter {
    fn operation_adapter(&self) -> &'static crate::payment::SimPaymentAdapter {
        static ADAPTER: std::sync::OnceLock<crate::payment::SimPaymentAdapter> =
            std::sync::OnceLock::new();
        ADAPTER.get_or_init(crate::payment::SimPaymentAdapter::new)
    }

    fn operation_authorization_id(reference: &str, amount_units: u64, currency: &str) -> String {
        let seed = format!("{reference}|{amount_units}|{currency}");
        let digest = chio_core::sha256_hex(seed.as_bytes());
        format!("sim-{}", &digest[..32])
    }
}

impl PaymentAdapter for FailingReleasePaymentAdapter {
    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        true
    }

    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "auth_failing_release".to_string(),
            settled: false,
            metadata: serde_json::json!({ "adapter": "failing-release" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "capture should not run".to_string(),
        ))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "injected payment release failure sk_live_abcdefghijklmnopqrstuvwx".to_string(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("refund should not run".to_string()))
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.operation_adapter().authorize_for_operation(
            operation_id,
            request_binding_hash,
            request,
        )
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        self.operation_adapter()
            .lookup_authorization_for_operation(operation_id, request_binding_hash)
    }

    fn capture_for_operation(
        &self,
        request: crate::payment::OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.operation_adapter().capture_for_operation(request)
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let _ = self.operation_adapter().settlement_state_for_operation(
            operation_id,
            request_binding_hash,
            reference,
            Some(authorization_id),
        )?;
        Err(PaymentError::RailError(
            "injected payment release failure sk_live_abcdefghijklmnopqrstuvwx".to_string(),
        ))
    }

    fn refund_for_operation(
        &self,
        request: crate::payment::OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.operation_adapter().refund_for_operation(request)
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.operation_adapter().settlement_state_for_operation(
            operation_id,
            request_binding_hash,
            reference,
            authorization_id,
        )
    }
}

#[test]
fn url_elicitation_monetary_release_failure_records_hold_ids_async(
) -> Result<(), Box<dyn std::error::Error>> {
    // When a MONETARY request hits UrlElicitationsRequired and the payment release
    // fails during cleanup, the append-only fault must name the stuck MONETARY hold
    // (the payment authorization id), not just the capability id, so an operator can
    // locate the hold to recover from the signed fault alone.
    let mut kernel = make_kernel(make_monetary_config());
    install_runtime_bounded_budget_authorities(
        &mut kernel,
        "url-monetary-release-failure-top-level",
    );
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel
        .set_payment_adapter(Box::new(FailingReleasePaymentAdapter))
        .expect("install payment adapter");

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1_000, "USD",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-elicitation-monetary-release-failure-async",
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "a monetary release failure must not replace the elicitation: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so release ran on the monetary arm"
    );
    // The stuck payment authorization id must land in the fault hold_ids.
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "payment_release",
        &FailingReleasePaymentAdapter::operation_authorization_id(
            "req-url-elicitation-monetary-release-failure-async",
            100,
            "USD",
        ),
    )?;
    Ok(())
}

#[test]
fn url_elicitation_public_metadata_rejects_forged_budget_authority_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_monetary_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1_000, "USD",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-cleanup-fault-forged-budget-authority",
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let error = kernel
        .evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(forged_budget_authority_metadata()),
        )
        .expect_err("caller budget authority metadata must fail before dispatch");
    assert!(matches!(
        error,
        KernelError::InvalidReceiptMetadata(reason) if reason.contains("budget_authority")
    ));
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        0,
        "reserved metadata must be rejected before the tool server runs"
    );
    assert_eq!(kernel.receipt_log().len(), 0);
    Ok(())
}

#[test]
fn url_elicitation_monetary_release_failure_records_hold_ids_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Nested-flow mirror of the async monetary-release-failure test: the
    // nested arm must ALSO name the stuck payment authorization id in the fault.
    let mut kernel = make_kernel(make_monetary_config());
    install_runtime_bounded_budget_authorities(&mut kernel, "url-monetary-release-failure-nested");
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel
        .set_payment_adapter(Box::new(FailingReleasePaymentAdapter))
        .expect("install payment adapter");

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1_000, "USD",
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-elicitation-monetary-release-failure-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-monetary-release-failure-nested",
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
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
        "the nested monetary release failure must not mask the elicitation: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so release ran on the monetary arm"
    );
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "payment_release",
        &FailingReleasePaymentAdapter::operation_authorization_id(
            "req-url-elicitation-monetary-release-failure-nested",
            100,
            "USD",
        ),
    )?;
    Ok(())
}
