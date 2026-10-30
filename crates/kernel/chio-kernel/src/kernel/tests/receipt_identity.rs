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
        let expected = match key {
            "chio_runtime" => {
                "chio_runtime is reserved for kernel-derived runtime admission reservations"
            }
            _ => "receipt_context is reserved for kernel-derived receipts",
        };
        assert!(
            matches!(&result, Err(KernelError::InvalidReceiptMetadata(reason)) if reason == expected),
            "caller metadata key {key}: {result:?}"
        );
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
    assert!(response.receipt.verify_integrity_embedded_key().unwrap());
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
    assert!(response.receipt.verify_integrity_embedded_key().unwrap());
}

#[test]
fn reusable_refusals_bind_identical_request_ids_to_distinct_tenants() {
    let (kernel, request, invocations) = fixture();
    let mut contexts = Vec::new();
    for tenant in ["tenant-a", "tenant-b"] {
        let session = kernel
            .open_session(request.agent_id.clone(), vec![request.capability.clone()])
            .unwrap();
        kernel
            .set_session_auth_context(
                &session,
                super::multi_tenant_receipt::oauth_auth_with_enterprise_tenant(tenant),
            )
            .unwrap();
        kernel.activate_session(&session).unwrap();
        contexts.push((
            tenant,
            make_operation_context(&session, &request.request_id, &request.agent_id),
        ));
    }
    kernel
        .emergency_stop("namespace isolation control")
        .unwrap();
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        dpop_proof: None,
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    }));
    let mut namespaces = Vec::new();
    for (tenant, context) in contexts {
        let response = session_tool_call(
            kernel
                .evaluate_session_operation(&context, &operation)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.receipt.tenant_id.as_deref(), Some(tenant));
        assert!(response.receipt.verify_integrity_embedded_key().unwrap());
        let metadata = response.receipt.metadata.as_ref().unwrap();
        assert_eq!(
            metadata["receipt_context"]["request_id"],
            request.request_id
        );
        assert_eq!(metadata["chio_runtime"]["identity_disposition"], "reusable");
        namespaces.push(
            metadata["receipt_context"]["request_namespace_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_ne!(namespaces[0], namespaces[1]);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}
