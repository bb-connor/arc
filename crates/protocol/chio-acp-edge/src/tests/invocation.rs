use crate::bridge::execute_orchestrated_acp_request;
use crate::error::AcpEdgeError;
use crate::metrics::{
    receipt_write_total, RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};
use crate::request_error::AcpRequestError;
use crate::tests::{
    assert_receipt_write_prometheus_sample_at_least, capability_for_tool, invalid_target_manifest,
    kernel_execution, manifest_public_key, mcp_target_manifest, metrics_test_guard, new_test_edge,
    openai_target_manifest, test_kernel_config, test_manifest,
    test_registry_from_unverified_manifests, test_server, threshold_artifacts, FailingToolServer,
};
use crate::{AcpEdgeConfig, AcpKernelExecutionContext};
use chio_core::crypto::Keypair;
use chio_cross_protocol::capability_bridge::CrossProtocolCapabilityRef;
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::execution::CrossProtocolExecutionRequest;
use chio_kernel::ChioKernel;
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_test_support::prelude::*;
use serde_json::{json, Value};

// ---- Invocation tests ----

#[test]
fn invoke_succeeds() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let result = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_unwrap();
    assert!(result.success);
    assert_eq!(result.data["result"], "ok");
    assert_eq!(
        result
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn invoke_unknown_tool_errors() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let err = edge
        .invoke("nonexistent", json!({}), &kernel, &execution)
        .test_expect_err("unknown ACP tool must fail");
    assert!(matches!(err, AcpEdgeError::ToolNotFound(_)));
}

#[test]
fn invoke_server_failure_returns_unsuccessful() {
    let manifest = ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "fail-srv".to_string(),
        name: "Fail".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "fail_tool".to_string(),
            description: "Fails".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(11),
    };
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![manifest]).test_unwrap();
    let (kernel, execution) =
        kernel_execution(Box::new(FailingToolServer), "fail-srv", "fail_tool");
    let result = edge
        .invoke("fail_tool", json!({}), &kernel, &execution)
        .test_unwrap();
    assert!(!result.success);
    assert!(result.error.is_some());
    assert_eq!(
        result
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn invoke_with_kernel_emits_signed_receipt_metadata() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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

    let result = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_unwrap();
    assert!(result.success);
    let metadata = result
        .metadata
        .test_expect("kernel path should attach metadata");
    assert!(metadata["chio"]["receiptId"].as_str().is_some());
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
        Some("acp")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(
        metadata["chio"]["receipt"]["capability_id"].as_str(),
        Some("cap-test-srv-read_file")
    );
}

#[test]
fn invoke_rejects_blank_execution_agent_id_before_dispatch() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: "\n".to_string(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_expect_err("blank ACP execution agent_id must fail");

    assert_eq!(
        error.to_string(),
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn invoke_rejects_supplemental_authorization_without_stable_request_id() {
    let edge = new_test_edge(
        AcpEdgeConfig {
            peer_capabilities: chio_mcp_edge::authorization::authorization_capabilities(),
            ..AcpEdgeConfig::default()
        },
        vec![test_manifest()],
    )
    .test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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
        supplemental_authorization: Some(
            chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                signed_extension: "opaque-extension".to_string(),
            },
        ),
        model_metadata: None,
    };

    let error = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_expect_err("supplemental authorization must require a stable request id");

    assert_eq!(
        error.to_string(),
        "urn:chio:error:transport:invalid-request-shape"
    );

    edge.invoke_with_request_id(
        "caller-chosen-request",
        "read_file",
        json!({"path": "/tmp"}),
        &kernel,
        &execution,
    )
    .test_expect("stable request id path must accept request-bound artifacts");
}

#[test]
fn invoke_rejects_singular_approval_token_without_stable_request_id() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let (approvals, _proposal) = threshold_artifacts(&subject, "acp-singular-auth");
    let approval_token = approvals
        .into_iter()
        .next()
        .test_expect("threshold artifacts must yield at least one approval token");
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: Some(approval_token.clone()),
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_expect_err("a singular approval token must require a stable request id");

    assert_eq!(
        error.to_string(),
        "urn:chio:error:transport:invalid-request-shape"
    );

    edge.invoke_with_request_id(
        "caller-chosen-request",
        "read_file",
        json!({"path": "/tmp"}),
        &kernel,
        &execution,
    )
    .test_expect("stable request id path must accept a singular approval token");
}

#[test]
fn invoke_rejects_control_character_execution_agent_id_before_dispatch() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: format!("{}{}suffix", subject.public_key().to_hex(), '\u{7}'),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_expect_err("control character ACP execution agent_id must fail");

    assert_eq!(
        error.to_string(),
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn invoke_with_kernel_denial_still_emits_receipt_metadata() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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

    let result = edge
        .invoke("write_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_unwrap();
    assert!(!result.success);
    let metadata = result
        .metadata
        .test_expect("deny path should attach metadata");
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
    assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
}

#[test]
fn pending_approval_is_not_reported_as_success() {
    let _metrics_guard = metrics_test_guard();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let before_pending = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
    let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

    let result = edge
        .project_pending_approval_for_test(
            "read_file",
            json!({"path": "/tmp"}),
            &kernel,
            &AcpKernelExecutionContext {
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
            },
            "approval required",
        )
        .test_unwrap();
    let metadata = result
        .metadata
        .test_expect("pending approval should attach metadata");

    assert!(!result.success);
    assert_eq!(result.error.as_deref(), Some("approval required"));
    assert_eq!(
        metadata["chio"]["decision"].as_str(),
        Some("pending_approval")
    );
    let pending_total = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
    assert!(pending_total > before_pending);
    assert_receipt_write_prometheus_sample_at_least(
        RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
        pending_total,
    );
    assert_eq!(
        receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
        before_error
    );
}

#[test]
fn invoke_kernel_error_records_receipt_write_error_outcome() {
    let _metrics_guard = metrics_test_guard();
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut config = test_kernel_config();
    config.require_web3_evidence = true;
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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
    let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

    let error = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_expect_err("ACP web3 evidence prerequisite failure must reject");

    assert!(std::error::Error::source(&error)
        .test_expect("local bridge cause")
        .to_string()
        .contains("web3 evidence prerequisites unavailable"));
    assert!(
        receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
        "acp orchestrator error path must advance receipt write error"
    );
}

#[test]
fn pre_kernel_bridge_error_does_not_record_receipt_write_error_outcome() {
    let _metrics_guard = metrics_test_guard();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "read_file");
    let capability_ref = CrossProtocolCapabilityRef {
        chio_capability_id: "wrong-capability".to_string(),
        origin_protocol: DiscoveryProtocol::Acp,
        protocol_context: Some(json!({ "capabilityId": "read_file" })),
        parent_capability_hash: "wrong-parent-hash".to_string(),
    };
    let arguments = json!({ "path": "/tmp" });
    let registry = test_registry_from_unverified_manifests(&[test_manifest()]).test_unwrap();
    let request = CrossProtocolExecutionRequest {
        origin_request_id: "acp-pre-kernel-mismatch".to_string(),
        kernel_request_id: "acp-pre-kernel-mismatch-kernel".to_string(),
        target_protocol: DiscoveryProtocol::Native,
        target_server_id: "test-srv".to_string(),
        target_tool_name: "read_file".to_string(),
        bridge_security: registry
            .bridge_security("test-srv", "read_file")
            .test_unwrap(),
        agent_id: subject.public_key().to_hex(),
        arguments: arguments.clone(),
        capability,
        source_envelope: json!({
            "capabilityId": "read_file",
            "arguments": arguments,
            "metadata": {
                "chio": {
                    "capabilityRef": serde_json::to_value(capability_ref).test_unwrap()
                }
            }
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        authenticated_session_id: None,
        security_context: None,
    };
    let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

    let error = execute_orchestrated_acp_request(&Default::default(), &kernel, &registry, request)
        .test_expect_err("ACP capability reference mismatch must reject");

    assert!(std::error::Error::source(&error)
        .test_expect("local bridge cause")
        .to_string()
        .contains("capability reference mismatch"));
    assert_eq!(
        receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
        before_error,
        "pre-kernel ACP bridge errors must not advance receipt write error"
    );
}

#[test]
fn invoke_with_mcp_target_emits_receipt_metadata_and_mcp_projection() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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

    let result = edge
        .invoke_with_mcp_target("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_unwrap();

    assert!(result.success);
    assert_eq!(result.data["isError"], Value::Bool(false));
    assert_eq!(
        result.data["structuredContent"]["result"].as_str(),
        Some("ok")
    );
    let metadata = result
        .metadata
        .test_expect("MCP target should attach metadata");
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
        Some("acp")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("mcp")
    );
    assert_eq!(
        metadata["chio"]["targetExecution"]["projectedResult"],
        Value::Bool(true)
    );
    assert_eq!(
        metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata["chio"]["bridge"]["route"]["selectedProtocols"],
        json!(["acp", "mcp", "native"])
    );
}

#[test]
fn default_invoke_honors_protocol_aware_target_binding() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![mcp_target_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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

    let result = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_unwrap();

    let metadata = result
        .metadata
        .test_expect("protocol-aware invoke should attach metadata");
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("mcp")
    );
    assert_eq!(
        metadata["chio"]["targetExecution"]["projectedResult"],
        Value::Bool(true)
    );
}

#[test]
fn default_invoke_supports_openai_target_binding() {
    let edge =
        new_test_edge(AcpEdgeConfig::default(), vec![openai_target_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

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

    let result = edge
        .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
        .test_unwrap();

    let metadata = result
        .metadata
        .test_expect("protocol-aware invoke should attach metadata");
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("open_ai")
    );
    assert_eq!(
        metadata["chio"]["targetExecution"]["projectedResult"],
        Value::Bool(true)
    );
    assert_eq!(result.data["type"].as_str(), Some("function_call_output"));
}

#[test]
fn invalid_target_protocol_metadata_is_rejected() {
    let error = match new_test_edge(AcpEdgeConfig::default(), vec![invalid_target_manifest()]) {
        Ok(_) => panic!("expected invalid target protocol metadata to fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AcpEdgeError::InvalidRequest(AcpRequestError::UnsupportedTarget)
    ));
}
