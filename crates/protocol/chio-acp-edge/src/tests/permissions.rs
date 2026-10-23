use super::*;
use crate::dpop_authority::ActivatedDpopAuthority;

// ---- Category inference tests ----

#[test]
fn read_file_gets_filesystem_category() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("read_file").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Filesystem);
}

#[test]
fn write_file_gets_filesystem_category() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("write_file").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Filesystem);
}

#[test]
fn exec_command_gets_terminal_category() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("exec_command").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Terminal);
}

#[test]
fn search_gets_default_tool_category() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("search").test_unwrap();
    assert_eq!(cap.category, AcpCategory::Tool);
}

// ---- Permission tests ----

#[test]
fn side_effect_tools_require_permission() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("write_file").test_unwrap();
    assert!(cap.requires_permission);
}

#[test]
fn permission_denied_by_default_for_required_caps() {
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let request = PermissionRequest {
        capability_id: "write_file".to_string(),
        arguments: json!({}),
    };
    assert_eq!(
        edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_denied_for_unknown_capability() {
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let request = PermissionRequest {
        capability_id: "nonexistent".to_string(),
        arguments: json!({}),
    };
    assert_eq!(
        edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_not_required_when_config_disabled() {
    let config = AcpEdgeConfig {
        require_permission: false,
        default_category: AcpCategory::Tool,
        ..AcpEdgeConfig::default()
    };
    let edge = new_test_edge(config, vec![test_manifest()]).test_unwrap();
    // read_file has no side effects and require_permission is false
    let cap = edge.capability("read_file").test_unwrap();
    assert!(!cap.requires_permission);
}

#[test]
fn permission_preview_allows_trusted_issuer_matching_scope() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
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
        edge.evaluate_permission_with_kernel(&request, &ChioKernel::new(config), &execution),
        PermissionDecision::Allow
    );
}

fn self_signed_read_file_execution(issuer: &Keypair) -> AcpKernelExecutionContext {
    let subject = Keypair::generate();
    AcpKernelExecutionContext {
        capability: capability_for_tool(issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    }
}

#[test]
fn permission_preview_refuses_untrusted_self_signed_issuer() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let kernel = ChioKernel::new(test_kernel_config());
    let issuer = Keypair::generate();
    let execution = self_signed_read_file_execution(&issuer);
    assert!(matches!(execution.capability.verify_integrity_embedded_key(), Ok(true)));
    assert!(!kernel.capability_issuer_is_trusted(&issuer.public_key()));
    let request = PermissionRequest {
        capability_id: "read_file".to_string(),
        arguments: json!({"path": "/tmp"}),
    };

    assert_eq!(
        edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_preview_without_trusted_issuers_never_allows() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut config = test_kernel_config();
    let issuer = Keypair::generate();
    config.ca_public_keys = Vec::new();
    let kernel = ChioKernel::new(config);
    let execution = self_signed_read_file_execution(&issuer);
    let request = PermissionRequest {
        capability_id: "read_file".to_string(),
        arguments: json!({"path": "/tmp"}),
    };

    assert_eq!(
        edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_with_capability_denies_sender_bound_scope_without_dpop() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
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
        edge.evaluate_permission_with_kernel(&request, &ChioKernel::new(config), &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_with_capability_denies_sender_bound_scope_with_mismatched_dpop() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut config = test_kernel_config();
    config.policy_hash = chio_core::sha256_hex(b"acp-dpop-policy");
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let authority = ActivatedDpopAuthority::install(&mut kernel, 300, 30).test_unwrap();
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
        &authority.domain,
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
        edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
        PermissionDecision::Deny
    );
}

#[test]
fn permission_preview_accepts_valid_dpop_without_consuming_invocation_nonce() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut config = test_kernel_config();
    config.policy_hash = chio_core::sha256_hex(b"acp-dpop-policy");
    let issuer = config.keypair.clone();
    let unconfigured_kernel = ChioKernel::new(KernelConfig {
        keypair: issuer.clone(),
        ca_public_keys: vec![issuer.public_key()],
        policy_hash: config.policy_hash.clone(),
        ..test_kernel_config()
    });
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let authority = ActivatedDpopAuthority::install(&mut kernel, 300, 30).test_unwrap();
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
        &authority.domain,
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
        edge.evaluate_permission_with_kernel(&request, &unconfigured_kernel, &execution),
        PermissionDecision::Deny
    );
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
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut config = test_kernel_config();
    config.policy_hash = chio_core::sha256_hex(b"acp-dpop-policy");
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let authority = ActivatedDpopAuthority::install(&mut kernel, 5, 0).test_unwrap();
    let subject = Keypair::generate();
    let capability = capability_for_tool_with_dpop_requirement(
        &issuer,
        &subject,
        "test-srv",
        "read_file",
        Some(true),
    );
    let request_arguments = json!({"path": "/tmp"});
    let mut stale_body = dpop_proof_for_request(
        &subject,
        &capability,
        "test-srv",
        "read_file",
        &request_arguments,
        "acp-preview-kernel-dpop-config",
        &authority.domain,
    )
    .body;
    stale_body.issued_at = current_unix_timestamp().saturating_sub(60);
    let stale_under_kernel_config = dpop::DpopProof::sign(stale_body, &subject).test_unwrap();
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

    let response = edge.handle_jsonrpc_value(
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
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
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
        edge.evaluate_permission_with_kernel(&request, &ChioKernel::new(config), &execution),
        PermissionDecision::Deny
    );
}
