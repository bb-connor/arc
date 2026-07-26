fn manifest_security_fixture() -> (
    ChioKernel,
    ToolCallRequest,
    chio_manifest::VerifiedManifestRegistry,
    chio_manifest::BridgeSecurityMetadata,
) {
    manifest_security_fixture_with_flow(Some(
        chio_manifest::ToolFlowDeclaration::new(None, None, false, Default::default()).unwrap(),
    ))
}

fn manifest_security_fixture_with_flow(
    flow: Option<chio_manifest::ToolFlowDeclaration>,
) -> (
    ChioKernel,
    ToolCallRequest,
    chio_manifest::VerifiedManifestRegistry,
    chio_manifest::BridgeSecurityMetadata,
) {
    manifest_security_fixture_with_flow_and_schema(flow, serde_json::json!({"type": "object"}))
}

fn manifest_security_fixture_with_flow_and_schema(
    flow: Option<chio_manifest::ToolFlowDeclaration>,
    input_schema: serde_json::Value,
) -> (
    ChioKernel,
    ToolCallRequest,
    chio_manifest::VerifiedManifestRegistry,
    chio_manifest::BridgeSecurityMetadata,
) {
    let kernel = make_kernel(make_config());
    let subject = Keypair::generate();
    let capability = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("manifest-server", "echo")]),
        300,
    );
    let request = make_request(
        "manifest-security-request",
        &capability,
        "echo",
        "manifest-server",
    );
    let signer = Keypair::from_seed(&[73; 32]);
    let manifest = chio_manifest::ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "manifest-server".to_string(),
        name: "Manifest security fixture".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![chio_manifest::ToolDefinition {
            name: "echo".to_string(),
            description: "Echo".to_string(),
            input_schema,
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer).unwrap();
    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry
        .register_public_only(
            signed,
            &signer.public_key(),
            chio_manifest::RuntimeToolTopology::local(),
        )
        .unwrap();
    let security = registry.bridge_security("manifest-server", "echo").unwrap();
    (kernel, request, registry, security)
}

fn manifest_security_local_fixture() -> (
    ChioKernel,
    ToolCallRequest,
    chio_manifest::VerifiedManifestRegistry,
    chio_manifest::BridgeSecurityMetadata,
) {
    manifest_security_fixture_with_flow(None)
}

fn manifest_security_constrained_local_fixture() -> (
    ChioKernel,
    ToolCallRequest,
    chio_manifest::VerifiedManifestRegistry,
    chio_manifest::BridgeSecurityMetadata,
) {
    manifest_security_fixture_with_flow_and_schema(
        None,
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 32}
            },
            "required": ["path"],
            "additionalProperties": false
        }),
    )
}

#[test]
fn generic_kernel_metadata_entrypoints_reject_reserved_manifest_sidecars() {
    let (kernel, request, _, _) = manifest_security_fixture();
    let forged = Some(serde_json::json!({
        "chio_manifest_security_v1": {
            "manifest_digest": "caller-asserted"
        }
    }));

    let blocking = kernel
        .evaluate_tool_call_blocking_with_metadata(&request, forged.clone())
        .unwrap_err();
    let planned_deny = kernel
        .sign_planned_deny_response(&request, "planned deny", forged)
        .unwrap_err();

    assert!(matches!(blocking, KernelError::InvalidReceiptMetadata(_)));
    assert!(matches!(
        planned_deny,
        KernelError::InvalidReceiptMetadata(_)
    ));
}

#[test]
fn caller_protocol_admission_metadata_is_rejected_before_dispatch() {
    let (mut kernel, request, registry, security) = manifest_security_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let forged = Some(serde_json::json!({
        "protocol_admission": {
            "invocation_capture": {
                "authorityCommitIndex": 999999
            }
        }
    }));

    let blocking = kernel
        .evaluate_tool_call_blocking_with_metadata(&request, forged.clone())
        .unwrap_err();
    let registry_validated = kernel
        .evaluate_tool_call_blocking_with_manifest_security(
            &request,
            &registry,
            &security,
            forged.clone(),
        )
        .unwrap_err();
    let planned_deny = kernel
        .sign_planned_deny_response(&request, "planned deny", forged)
        .unwrap_err();

    assert!(matches!(blocking, KernelError::InvalidReceiptMetadata(_)));
    assert!(matches!(
        registry_validated,
        KernelError::InvalidReceiptMetadata(_)
    ));
    assert!(matches!(
        planned_deny,
        KernelError::InvalidReceiptMetadata(_)
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn caller_budget_authority_metadata_is_rejected_before_receipt_or_dispatch() {
    let (mut kernel, request, registry, security) = manifest_security_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let forged = Some(serde_json::json!({
        "budget_authority": {
            "guarantee_level": "partition_escrowed",
            "partition_escrow": {
                "canonical_json": "{}",
                "evidence_digest": "00"
            }
        }
    }));

    let blocking = kernel
        .evaluate_tool_call_blocking_with_metadata(&request, forged.clone())
        .unwrap_err();
    let registry_validated = kernel
        .evaluate_tool_call_blocking_with_manifest_security(
            &request,
            &registry,
            &security,
            forged.clone(),
        )
        .unwrap_err();
    let planned_deny = kernel
        .sign_planned_deny_response(&request, "planned deny", forged)
        .unwrap_err();

    for error in [blocking, registry_validated, planned_deny] {
        assert!(matches!(
            error,
            KernelError::InvalidReceiptMetadata(reason)
                if reason.contains("budget_authority")
        ));
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn future_budget_denial_authority_namespace_is_already_reserved() {
    let forged = serde_json::json!({
        "budget_denial_authority": {
            "guarantee_level": "partition_escrowed",
            "decision": "denied"
        }
    });

    assert!(matches!(
        reject_reserved_receipt_metadata(Some(&forged)),
        Err(KernelError::InvalidReceiptMetadata(reason))
            if reason.contains("budget_denial_authority")
    ));
}

#[test]
fn manifest_secured_dispatch_rejects_flow_registry_without_governed_runtime() {
    let (kernel, request, registry, security) = manifest_security_fixture();

    assert!(registry.requires_flow_runtime());
    assert!(!kernel.has_installed_flow_runtime());
    let error = kernel
        .evaluate_tool_call_blocking_with_manifest_security(&request, &registry, &security, None)
        .unwrap_err();

    assert!(matches!(error, KernelError::FlowRuntimeUnavailable));
}

#[test]
fn combined_manifest_and_security_context_entrypoint_reaches_enforced_dispatch() {
    let (mut kernel, request, registry, security) = manifest_security_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook_calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(std::sync::Arc::clone(&hook_calls), None);
    kernel.set_security_pre_dispatch_hook(capture.hook);
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let security_context = security_pre_dispatch_context_for(&request, "manifest-context", 21);

    let response = kernel
        .evaluate_tool_call_blocking_with_manifest_security_and_security_context(
            &request,
            &registry,
            &security,
            None,
            &security_context,
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        capture.contexts.lock().unwrap().as_slice(),
        std::slice::from_ref(&security_context)
    );
}

#[test]
fn combined_manifest_entrypoint_rejects_mismatched_security_principal() {
    let (kernel, request, registry, security) = manifest_security_local_fixture();
    let valid = security_pre_dispatch_context_for(&request, "manifest-binding", 22);
    let valid_v1 = valid.as_v1();
    let mismatched = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        valid_v1.tenant_id().clone(),
        valid_v1.session_id().clone(),
        chio_security_types::PrincipalId::new("different-manifest-principal").unwrap(),
        valid_v1.isolation_epoch_id().clone(),
        valid_v1.lineage_root_id().clone(),
        valid_v1.context_generation(),
    ));

    let error = kernel
        .evaluate_tool_call_blocking_with_manifest_security_and_security_context(
            &request,
            &registry,
            &security,
            None,
            &mismatched,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::GuardDenied(reason)
            if reason == "authoritative security context principal does not match the request agent"
    ));
}

#[test]
fn combined_manifest_authenticated_session_entrypoint_rejects_wrong_session() {
    let (mut kernel, request, registry, security) = manifest_security_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let authenticated_session_id = SessionId::new("manifest-authenticated-session");
    let wrong_context = security_pre_dispatch_context_for(&request, "manifest-foreign-session", 23);

    let error = kernel
        .evaluate_tool_call_blocking_with_manifest_security_and_authenticated_session_context(
            &request,
            &registry,
            &security,
            None,
            &authenticated_session_id,
            &wrong_context,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::GuardDenied(reason)
            if reason == "authoritative security context does not match the authenticated session"
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn manifest_entrypoint_without_context_denies_enforced_dispatch() {
    let (mut kernel, request, registry, security) = manifest_security_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook_calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(std::sync::Arc::clone(&hook_calls), None);
    kernel.set_security_pre_dispatch_hook(capture.hook);
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);

    let response = kernel
        .evaluate_tool_call_blocking_with_manifest_security(&request, &registry, &security, None)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn combined_session_manifest_entrypoint_rejects_context_for_another_session() {
    let (mut kernel, request, registry, security) = manifest_security_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![request.capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let operation_context =
        make_operation_context(&session_id, "manifest-session-mismatch", &request.agent_id);
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        supplemental_authorization: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    }));
    let wrong_context = security_pre_dispatch_context_for(&request, "another-session", 22);

    let error = kernel
        .evaluate_session_operation_with_manifest_security_and_security_context(
            &operation_context,
            &operation,
            &registry,
            &security,
            &wrong_context,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::GuardDenied(reason)
            if reason == "authoritative security context does not match the authenticated session"
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn typed_kernel_manifest_entrypoint_preserves_exact_sidecar_and_rejects_forgery() {
    let (kernel, request, registry, security) = manifest_security_fixture();
    let response = kernel
        .sign_planned_deny_response_with_manifest_security(
            &request,
            "planned deny",
            &registry,
            &security,
            None,
        )
        .unwrap();
    let actual = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_manifest_security_v1"))
        .unwrap();
    assert_eq!(
        chio_core::canonical_json_bytes(actual).unwrap(),
        chio_core::canonical_json_bytes(&serde_json::to_value(&security).unwrap()).unwrap()
    );

    let mut forged_value = serde_json::to_value(&security).unwrap();
    forged_value["manifest_digest"] = serde_json::Value::String("00".repeat(32));
    let forged: chio_manifest::BridgeSecurityMetadata =
        serde_json::from_value(forged_value).unwrap();
    let error = kernel
        .sign_planned_deny_response_with_manifest_security(
            &request,
            "planned deny",
            &registry,
            &forged,
            None,
        )
        .unwrap_err();
    assert!(matches!(error, KernelError::InvalidReceiptMetadata(_)));
}

#[test]
fn kernel_manifest_entrypoints_reject_invalid_arguments_before_receipt_or_dispatch_and_recover() {
    let (mut kernel, request, registry, security) = manifest_security_constrained_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let mut invalid = request.clone();
    invalid.request_id = "manifest-invalid-schema".to_string();
    invalid.arguments = serde_json::json!({"path": 7});
    let receipt_count_before = kernel.receipt_log().len();

    let execution_error = kernel
        .evaluate_tool_call_blocking_with_manifest_security(&invalid, &registry, &security, None)
        .unwrap_err();
    let planned_deny_error = kernel
        .sign_planned_deny_response_with_manifest_security(
            &invalid,
            "adapter planned deny",
            &registry,
            &security,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        execution_error,
        KernelError::InvalidReceiptMetadata(reason)
            if reason.contains("signed manifest input schema")
    ));
    assert!(matches!(
        planned_deny_error,
        KernelError::InvalidReceiptMetadata(reason)
            if reason.contains("signed manifest input schema")
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before);

    let response = kernel
        .evaluate_tool_call_blocking_with_manifest_security(&request, &registry, &security, None)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before + 1);
}

#[test]
fn session_manifest_entrypoint_rejects_invalid_arguments_before_receipt_or_dispatch_and_recovers() {
    let (mut kernel, request, registry, security) = manifest_security_constrained_local_fixture();
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "manifest-server",
        vec!["echo"],
        std::sync::Arc::clone(&invocations),
    )));
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![request.capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let operation_for = |arguments| {
        SessionOperation::ToolCall(Box::new(ToolCallOperation {
            capability: request.capability.clone(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            arguments,
            supplemental_authorization: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            execution_nonce: None,
            model_metadata: None,
            extra_metadata: None,
            declassification_grant: None,
        }))
    };
    let invalid_context = make_operation_context(
        &session_id,
        "manifest-session-schema-invalid",
        &request.agent_id,
    );
    let invalid_operation = operation_for(serde_json::json!({"path": 7}));
    let receipt_count_before = kernel.receipt_log().len();

    let error = kernel
        .evaluate_session_operation_with_manifest_security(
            &invalid_context,
            &invalid_operation,
            &registry,
            &security,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::InvalidReceiptMetadata(reason)
            if reason.contains("signed manifest input schema")
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before);

    let valid_context = make_operation_context(
        &session_id,
        "manifest-session-schema-valid",
        &request.agent_id,
    );
    let valid_operation = operation_for(request.arguments.clone());
    let response = kernel
        .evaluate_session_operation_with_manifest_security(
            &valid_context,
            &valid_operation,
            &registry,
            &security,
        )
        .unwrap();
    let response = session_tool_call(response).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before + 1);
}
