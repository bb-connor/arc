// ---- Category inference tests ----

#[test]
fn read_file_gets_filesystem_category() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("read_file").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Filesystem);
}

#[test]
fn write_file_gets_filesystem_category() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("write_file").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Filesystem);
}

#[test]
fn exec_command_gets_terminal_category() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("exec_command").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Terminal);
}

#[test]
fn search_gets_default_tool_category() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("search").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Tool);
}

// ---- Permission tests ----

#[test]
fn side_effect_tools_require_permission() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("write_file").test_unwrap();
    assert!(cap.requires_permission);
}

#[test]
fn permission_denied_by_default_for_required_caps() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let request = PermissionRequest {
        capability_id: "write_file".to_string(),
        arguments: json!({}),
    };
    assert_eq!(
        edge.compatibility().preview_permission(&request),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_denied_for_unknown_capability() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let request = PermissionRequest {
        capability_id: "nonexistent".to_string(),
        arguments: json!({}),
    };
    assert_eq!(
        edge.compatibility().preview_permission(&request),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_not_required_when_config_disabled() {
    let config = AcpEdgeConfig {
        require_permission: false,
        default_category: AcpCategory::Tool,
    };
    let edge = ChioAcpEdge::new(config, vec![test_manifest()]).test_unwrap();
    // read_file has no side effects and require_permission is false
    let cap = edge.capability("read_file").test_unwrap();
    assert!(!cap.requires_permission);
}

#[test]
fn permission_with_capability_allows_matching_scope() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let request = PermissionRequest {
        capability_id: "read_file".to_string(),
        arguments: json!({"path": "/tmp"}),
    };

    assert_eq!(
        edge.evaluate_permission(&request, &execution),
        PermissionDecision::Allow
    );
}

#[test]
fn permission_with_capability_denies_sender_bound_scope_without_dpop() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool_with_dpop_requirement(
            &issuer,
            &subject,
            "test-srv",
            "read_file",
            Some(true),
        ),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let request = PermissionRequest {
        capability_id: "read_file".to_string(),
        arguments: json!({"path": "/tmp"}),
    };

    assert_eq!(
        edge.evaluate_permission(&request, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_with_capability_denies_sender_bound_scope_with_mismatched_dpop() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let capability = capability_for_tool_with_dpop_requirement(
        &issuer,
        &subject,
        "test-srv",
        "read_file",
        Some(true),
    );
    let request_arguments = json!({"path": "/tmp"});
    let mismatched_proof = dpop_proof_for_request(
        &subject,
        &capability,
        "test-srv",
        "write_file",
        &request_arguments,
        "acp-preview-nonce-wrong-tool",
    );
    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: subject.public_key().to_hex(),
        dpop_proof: Some(mismatched_proof),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let request = PermissionRequest {
        capability_id: "read_file".to_string(),
        arguments: request_arguments,
    };

    assert_eq!(
        edge.evaluate_permission(&request, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_preview_accepts_valid_dpop_without_consuming_invocation_nonce() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    kernel.set_dpop_store(
        dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300)),
        dpop::DpopConfig::default(),
    );
    let subject = Keypair::generate();
    let capability = capability_for_tool_with_dpop_requirement(
        &issuer,
        &subject,
        "test-srv",
        "read_file",
        Some(true),
    );
    let request_arguments = json!({"path": "/tmp"});
    let proof = dpop_proof_for_request(
        &subject,
        &capability,
        "test-srv",
        "read_file",
        &request_arguments,
        "acp-preview-valid-invoke-nonce",
    );
    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: subject.public_key().to_hex(),
        dpop_proof: Some(proof),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let request = PermissionRequest {
        capability_id: "read_file".to_string(),
        arguments: request_arguments.clone(),
    };

    assert_eq!(
        edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
        PermissionDecision::Allow
    );
    let result = edge
        .invoke("read_file", request_arguments, &kernel, &execution)
        .test_expect("valid DPoP proof should remain usable for invoke");
    assert!(result.success);
}

#[test]
fn jsonrpc_permission_preview_uses_kernel_dpop_config() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.set_dpop_store(
        dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300)),
        dpop::DpopConfig {
            proof_ttl_secs: 5,
            max_clock_skew_secs: 0,
            nonce_store_capacity: 1024,
        },
    );
    let subject = Keypair::generate();
    let capability = capability_for_tool_with_dpop_requirement(
        &issuer,
        &subject,
        "test-srv",
        "read_file",
        Some(true),
    );
    let request_arguments = json!({"path": "/tmp"});
    let stale_under_kernel_config = dpop_proof_for_request_issued_at(
        &subject,
        &capability,
        "test-srv",
        "read_file",
        &request_arguments,
        "acp-preview-kernel-dpop-config",
        current_unix_timestamp().saturating_sub(60),
    );
    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: subject.public_key().to_hex(),
        dpop_proof: Some(stale_under_kernel_config),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let response = edge.handle_jsonrpc(
        json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "session/request_permission",
            "params": {
                "capabilityId": "read_file",
                "arguments": request_arguments
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(
        response["result"]["decision"],
        serde_json::to_value(PermissionDecision::Deny).test_unwrap()
    );
}

#[test]
fn permission_with_capability_denies_out_of_scope_request() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let request = PermissionRequest {
        capability_id: "write_file".to_string(),
        arguments: json!({"path": "/tmp"}),
    };

    assert_eq!(
        edge.evaluate_permission(&request, &execution),
        PermissionDecision::Deny
    );
}
