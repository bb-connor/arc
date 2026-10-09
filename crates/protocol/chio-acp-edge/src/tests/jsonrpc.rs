use crate::bridge::MAX_DEFERRED_ACP_TASKS;
use crate::error::AcpEdgeError;
use crate::tests::{
    capability_for_tool, kernel_execution, new_test_edge, streaming_manifest, test_kernel_config,
    test_manifest, test_server, CountingToolServer, DenyingAcpRuntimeAdmissionHook, MockToolServer,
};
use crate::{AcpEdgeConfig, AcpKernelExecutionContext, ChioAcpEdge};
use chio_core::crypto::Keypair;
use chio_kernel::ChioKernel;
use chio_test_support::prelude::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ---- JSON-RPC handler tests ----

#[test]
fn jsonrpc_param_helpers_validate_capability_and_default_arguments() {
    let missing = match ChioAcpEdge::jsonrpc_permission_request(&json!({})) {
        Ok(_) => panic!("expected missing capabilityId to fail"),
        Err(error) => error,
    };
    assert_eq!(
        missing.to_string(),
        "urn:chio:error:transport:invalid-request-shape"
    );

    let permission = ChioAcpEdge::jsonrpc_permission_request(&json!({
        "capabilityId": "read_file",
        "arguments": { "path": "/workspace/README.md" }
    }))
    .test_unwrap();
    assert_eq!(permission.capability_id, "read_file");
    assert_eq!(
        permission.arguments,
        json!({ "path": "/workspace/README.md" })
    );

    let non_string = match ChioAcpEdge::jsonrpc_invocation_params(
        &json!({
            "capabilityId": 7,
            "arguments": ["kept"]
        }),
        "tool/invoke",
    ) {
        Ok(_) => panic!("expected non-string capabilityId to fail"),
        Err(error) => error,
    };
    assert_eq!(
        non_string.to_string(),
        "urn:chio:error:transport:invalid-request-shape"
    );

    let (capability_id, default_arguments) = ChioAcpEdge::jsonrpc_invocation_params(
        &json!({
            "capabilityId": "search"
        }),
        "tool/invoke",
    )
    .test_unwrap();
    assert_eq!(capability_id, "search");
    assert_eq!(default_arguments, json!({}));
}

#[test]
fn jsonrpc_list_capabilities() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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
    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session/list_capabilities",
            "params": {}
        }),
        &kernel,
        &execution,
    );
    let caps = response["result"]["capabilities"].as_array().test_unwrap();
    assert_eq!(caps.len(), 4);
    assert_eq!(
        response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(
        response["result"]["metadata"]["chio"]["invokeMode"].as_str(),
        Some("blocking_or_deferred_task")
    );
    assert_eq!(
        response["result"]["metadata"]["chio"]["lifecycle"]["toolStream"].as_str(),
        Some("deferred_task_resume")
    );
    assert_eq!(
        response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
        Some("acp_authoritative")
    );
}

#[test]
fn jsonrpc_request_permission() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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
    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session/request_permission",
            "params": {
                "capabilityId": "read_file",
                "arguments": {"path": "/tmp"}
            }
        }),
        &kernel,
        &execution,
    );
    assert!(response.get("result").is_some());
    assert_eq!(
        response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("capability_preview")
    );

    assert_eq!(
        response["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn jsonrpc_permission_rejects_padded_execution_agent_id_before_preview() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: format!(" {} ", subject.public_key().to_hex()),
        dpop_proof: None,
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
            "id": 49,
            "method": "session/request_permission",
            "params": {
                "capabilityId": "read_file",
                "arguments": {"path": "/tmp"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"].as_str(),
        Some("urn:chio:error:transport:invalid-request-shape")
    );
}

#[test]
fn jsonrpc_request_permission_rejects_empty_capability_id_before_preview() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "session/request_permission",
            "params": {
                "capabilityId": "  ",
                "arguments": {"path": "/tmp"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_request_permission_rejects_padded_capability_id_before_preview() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "session/request_permission",
            "params": {
                "capabilityId": " read_file ",
                "arguments": {"path": "/tmp"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_request_permission_rejects_control_character_capability_id_before_preview() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 47,
            "method": "session/request_permission",
            "params": {
                "capabilityId": "read_file\nwrite_file",
                "arguments": {"path": "/tmp"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_tool_invoke() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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
    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tool/invoke",
            "params": {
                "capabilityId": "search",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );
    assert!(response["result"]["success"].as_bool().unwrap_or(false));
    assert_eq!(
        response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn jsonrpc_tool_invoke_rejects_non_string_capability_id_before_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tool/invoke",
            "params": {
                "capabilityId": 7,
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_tool_invoke_rejects_padded_capability_id_before_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 45,
            "method": "tool/invoke",
            "params": {
                "capabilityId": " search ",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_tool_invoke_rejects_control_character_capability_id_before_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 48,
            "method": "tool/invoke",
            "params": {
                "capabilityId": "search\nread_file",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_list_capabilities_rejects_non_object_params_before_listing() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "session/list_capabilities",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_tool_invoke_rejects_non_object_params_before_capability_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 45,
            "method": "tool/invoke",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_resume_rejects_non_object_params_before_task_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 46,
            "method": "tool/resume",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_unknown_method() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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
    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown/method",
            "params": {}
        }),
        &kernel,
        &execution,
    );
    assert_eq!(response["error"]["code"], -32601);
}

#[test]
fn jsonrpc_rejects_non_scalar_request_ids_before_method_dispatch() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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

    for invalid_id in [json!(false), json!({"nested": 1}), json!([1])] {
        let response = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": invalid_id,
                "method": "unknown/method",
                "params": {}
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(
            response["error"]["message"],
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
}

#[test]
fn jsonrpc_invalid_version_preserves_scalar_request_id() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "1.0",
            "id": "request-7",
            "method": "session/list_capabilities",
            "params": {}
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["id"], "request-7");
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_permission_rejects_non_object_params_before_preview() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 47,
            "method": "session/request_permission",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "urn:chio:error:transport:invalid-request-shape"
    );
}

#[test]
fn jsonrpc_kernel_paths_mark_authority_and_permission_preview() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "search");

    let listed = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "session/list_capabilities",
            "params": {}
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        listed["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );

    let permission = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "session/request_permission",
            "params": {
                "capabilityId": "read_file",
                "arguments": {"path": "/tmp"}
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        permission["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("capability_preview")
    );
    assert_eq!(
        permission["result"]["metadata"]["chio"]["previewOnly"].as_bool(),
        Some(true)
    );

    assert_eq!(
        permission["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );

    let invoke = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tool/invoke",
            "params": {
                "capabilityId": "search",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        invoke["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(
        invoke["result"]["metadata"]["chio"]["authoritative"].as_bool(),
        Some(true)
    );
}

#[test]
fn jsonrpc_stream_creates_deferred_task_and_resume_resolves_result() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(MockToolServer {
        server_id: "streaming-srv".to_string(),
        tools: vec!["search_stream".to_string()],
        response: json!({"content": [{"text": "chunk-1"}, {"text": "chunk-2"}]}),
    }));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        response["result"]["task"]["status"].as_str(),
        Some("working")
    );
    let task_id = response["result"]["task"]["id"]
        .as_str()
        .test_expect("tool/stream should create task")
        .to_string();
    assert_eq!(
        response["result"]["task"]["metadata"]["chio"]["receiptPending"].as_bool(),
        Some(true)
    );
    assert_eq!(
        response["result"]["task"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"]
            .as_str(),
        Some("tool/stream")
    );

    let resumed = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tool/resume",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        resumed["result"]["task"]["status"].as_str(),
        Some("completed")
    );
    assert_eq!(
        resumed["result"]["result"]["metadata"]["chio"]["receiptId"]
            .as_str()
            .map(|value| !value.is_empty()),
        Some(true)
    );
    assert!(resumed["result"]["result"]["data"]["content"].is_array());
}

#[test]
fn jsonrpc_resume_runtime_admission_denies_before_stream_tool_dispatch() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let tool_calls = Arc::new(AtomicU64::new(0));
    let admission_calls = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        calls: Arc::clone(&tool_calls),
    }));
    kernel.set_runtime_admission_hook(Arc::new(DenyingAcpRuntimeAdmissionHook {
        calls: Arc::clone(&admission_calls),
    }));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    let created = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 70,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );
    let task_id = created["result"]["task"]["id"]
        .as_str()
        .test_expect("tool/stream should create task")
        .to_string();

    let resumed = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 71,
            "method": "tool/resume",
            "params": { "taskId": task_id }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
    assert_eq!(resumed["result"]["task"]["status"].as_str(), Some("failed"));
    assert_eq!(
        resumed["result"]["result"]["error"].as_str(),
        Some("acp runtime admission denied")
    );
    assert_eq!(
        resumed["result"]["result"]["metadata"]["chio"]["decision"].as_str(),
        Some("deny")
    );
    assert_eq!(
        resumed["result"]["result"]["metadata"]["chio"]["reason"].as_str(),
        Some("acp runtime admission denied")
    );
}

#[test]
fn jsonrpc_stream_notification_creates_task_without_response() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert!(response.is_notification());
    assert_eq!(edge.tasks.borrow().len(), 1);
}

#[test]
fn jsonrpc_resume_retains_completed_deferred_task_result() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(MockToolServer {
        server_id: "streaming-srv".to_string(),
        tools: vec!["search_stream".to_string()],
        response: json!({"content": [{"text": "chunk-1"}]}),
    }));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    let created = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );
    let task_id = created["result"]["task"]["id"]
        .as_str()
        .test_unwrap()
        .to_string();

    let resumed = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tool/resume",
            "params": { "taskId": task_id.clone() }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(
        resumed["result"]["task"]["status"].as_str(),
        Some("completed")
    );
    assert!(edge.tasks.borrow().contains_key(&task_id));

    let repeated = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tool/resume",
            "params": { "taskId": task_id.clone() }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        repeated["result"]["task"]["status"].as_str(),
        Some("completed")
    );
    assert_eq!(
        repeated["result"]["result"]["metadata"]["chio"]["receiptId"],
        resumed["result"]["result"]["metadata"]["chio"]["receiptId"]
    );
}

#[test]
fn jsonrpc_lifecycle_rejects_empty_task_id_before_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    for method in ["tool/cancel", "tool/resume"] {
        let response = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": 43,
                "method": method,
                "params": {
                    "taskId": ""
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
}

#[test]
fn jsonrpc_lifecycle_rejects_padded_task_id_before_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    for method in ["tool/cancel", "tool/resume"] {
        let response = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": 46,
                "method": method,
                "params": {
                    "taskId": " acp-task-1 "
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
}

#[test]
fn jsonrpc_lifecycle_rejects_control_character_task_id_before_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    for method in ["tool/cancel", "tool/resume"] {
        let response = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": 49,
                "method": method,
                "params": {
                    "taskId": "acp-task-1\nacp-task-2"
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
}

#[test]
fn jsonrpc_stream_rejects_deferred_task_map_over_cap() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    for index in 0..1_024 {
        let response = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": index,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            response["result"]["task"]["status"].as_str(),
            Some("working")
        );
    }

    let rejected = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 2_000,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert!(matches!(
        rejected.local_error(),
        Some(AcpEdgeError::TaskCapacity)
    ));
}

#[test]
fn jsonrpc_stream_rejects_padded_execution_agent_id_before_task_retention() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
        agent_id: format!(" {} ", subject.public_key().to_hex()),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let rejected = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 2_500,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(rejected["error"]["code"], -32602);
    assert_eq!(
        rejected["error"]["message"].as_str(),
        Some("urn:chio:error:transport:invalid-request-shape")
    );
    assert!(edge.tasks.borrow().is_empty());
}

#[test]
fn jsonrpc_stream_capacity_includes_retained_cancelled_deferred_tasks() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    for index in 0..MAX_DEFERRED_ACP_TASKS {
        let created = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": index,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            created["result"]["task"]["status"].as_str(),
            Some("working")
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should return task id")
            .to_string();

        let cancelled = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": index + MAX_DEFERRED_ACP_TASKS,
                "method": "tool/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled["result"]["task"]["status"].as_str(),
            Some("cancelled")
        );
    }

    assert_eq!(edge.tasks.borrow().len(), MAX_DEFERRED_ACP_TASKS);

    let accepted = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 3_000,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );

    assert!(matches!(
        accepted.local_error(),
        Some(AcpEdgeError::TaskCapacity)
    ));
    assert_eq!(edge.tasks.borrow().len(), MAX_DEFERRED_ACP_TASKS);
}

#[test]
fn jsonrpc_cancel_marks_deferred_stream_task_cancelled() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

    let created = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tool/stream",
            "params": {
                "capabilityId": "search_stream",
                "arguments": {"query": "test"}
            }
        }),
        &kernel,
        &execution,
    );
    let task_id = created["result"]["task"]["id"]
        .as_str()
        .test_unwrap()
        .to_string();

    let cancelled = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tool/cancel",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        cancelled["result"]["task"]["status"].as_str(),
        Some("cancelled")
    );
    assert_eq!(
        cancelled["result"]["task"]["metadata"]["chio"]["decision"].as_str(),
        Some("cancelled")
    );

    let cancelled_again = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tool/cancel",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        cancelled_again["result"]["task"]["status"].as_str(),
        Some("cancelled")
    );
    assert_eq!(
        cancelled_again["result"]["task"]["metadata"]["chio"]["decision"].as_str(),
        Some("cancelled")
    );
}

#[test]
fn jsonrpc_cancel_rejects_missing_task_identity() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tool/cancel",
            "params": {
                "capabilityId": "search_stream"
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(response["error"]["code"], -32602);
    assert!(response.local_error().is_some());
}
