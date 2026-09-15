/// Sibling-sum delegation fixture whose child capabilities target a tool server
/// that returns `UrlElicitationsRequired` after dispatch entry. Parent share
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
    kernel.set_capability_trust_root(
        kernel.config.keypair.public_key(),
        scope_hash(&parent_scope).unwrap(),
    );

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel,
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
        kernel: &kernel,
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
fn non_durable_url_elicitation_retains_sibling_budget() -> Result<(), Box<dyn std::error::Error>> {
    // Refcount: admit_capability_budget takes a holder lease per evaluation. An
    // earlier evaluation holds child_a's edge (lease 1). A second overlapping
    // evaluation that reaches dispatch takes a second lease and retains it when
    // URL elicitation is returned. Releasing the earlier lease must leave the
    // dispatch lease in place.
    let SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp: _child_a_kp,
        path: _path,
        ..
    } = make_sibling_sum_url_fixture("chio-runtime-url-idempotent-readmit");

    // Earlier evaluation holds child_a's edge (lease 1) for the duration.
    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission must acquire child_a's lease");

    // The overlapping evaluation takes a second lease before dispatch.
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
    assert!(kernel.admit_capability_budget(&child_b).is_err());
    Ok(())
}

#[test]
fn non_durable_url_elicitation_retains_sibling_budget_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // The nested-flow arm must retain its holder lease after dispatch entry.
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
    assert!(kernel.admit_capability_budget(&child_b).is_err());
    Ok(())
}
