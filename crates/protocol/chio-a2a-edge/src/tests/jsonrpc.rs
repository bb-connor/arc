use crate::bridge::MAX_DEFERRED_A2A_TASKS;
use crate::config::A2aEdgeConfig;
use crate::edge::ChioA2aEdge;
use crate::error::A2aEdgeError;
use crate::tests::{
    capability_for_tool, invalid_target_manifest, kernel_for_server, mcp_target_manifest,
    openai_target_manifest, stream_manifest, test_kernel_config, test_manifest, test_server,
    text_message, CountingStreamingToolServer, DenyingRuntimeAdmissionHook, StreamingToolServer,
};
use crate::types::{
    A2aKernelExecutionContext, A2aMessage, A2aPart, SendMessageRequest, TaskStatus,
};
use chio_core::crypto::Keypair;
use chio_kernel::ChioKernel;
use chio_test_support::prelude::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ---- JSON-RPC handler tests ----

#[test]
fn jsonrpc_send_message_param_parser_infers_single_skill_and_labels_stream_errors() {
    let edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut manifest = test_manifest();
            manifest.tools.truncate(1);
            manifest
        }],
    )
    .test_unwrap();

    let (skill_id, request) = edge
        .parse_jsonrpc_send_message_params(
            serde_json::to_value(text_message("hi")).test_unwrap(),
            "SendMessage",
        )
        .test_unwrap();
    assert_eq!(skill_id, "echo");
    assert_eq!(request.message.role, "user");

    let error = match edge.parse_jsonrpc_send_message_params(
        json!({
            "message": {
                "role": "user",
                "parts": "bad"
            }
        }),
        "SendStreamingMessage",
    ) {
        Ok(_) => panic!("expected invalid request error"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        A2aEdgeError::UntrustedInput(chio_core::canonical::UntrustedJsonError::Decode(_))
    ));
}

#[test]
fn jsonrpc_send_message_param_parser_requires_skill_id_for_multiple_skills() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();

    let error = match edge.parse_jsonrpc_send_message_params(
        json!({
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": "hi"}]
            }
        }),
        "SendMessage",
    ) {
        Ok(_) => panic!("expected missing target skill error"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(
        message,
        "metadata.chio.targetSkillId is required when multiple skills are exposed"
    );
}

#[test]
fn jsonrpc_single_skill_rejects_malformed_chio_metadata() {
    let edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut manifest = test_manifest();
            manifest.tools.truncate(1);
            manifest
        }],
    )
    .test_unwrap();

    let error = match edge.parse_jsonrpc_send_message_params(
        json!({
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": "hi"}]
            },
            "metadata": {
                "chio": "not-an-object"
            }
        }),
        "SendMessage",
    ) {
        Ok(_) => panic!("expected malformed metadata.chio to fail"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(message, "metadata.chio must be a JSON object");
}

#[test]
fn jsonrpc_single_skill_rejects_non_string_target_skill_id() {
    let edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut manifest = test_manifest();
            manifest.tools.truncate(1);
            manifest
        }],
    )
    .test_unwrap();

    let error = match edge.parse_jsonrpc_send_message_params(
        json!({
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": "hi"}]
            },
            "metadata": {
                "chio": {"targetSkillId": 123}
            }
        }),
        "SendMessage",
    ) {
        Ok(_) => panic!("expected non-string targetSkillId to fail"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(message, "metadata.chio.targetSkillId must be a string");
}

#[test]
fn jsonrpc_single_skill_rejects_empty_target_skill_id_before_lookup() {
    let edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut manifest = test_manifest();
            manifest.tools.truncate(1);
            manifest
        }],
    )
    .test_unwrap();

    let error = match edge.parse_jsonrpc_send_message_params(
        json!({
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": "hi"}]
            },
            "metadata": {
                "chio": {"targetSkillId": "   "}
            }
        }),
        "SendMessage",
    ) {
        Ok(_) => panic!("expected empty targetSkillId to fail before lookup"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(message, "metadata.chio.targetSkillId must not be empty");
}

#[test]
fn jsonrpc_rejects_padded_target_skill_id_before_lookup() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();

    let error = match edge.parse_jsonrpc_send_message_params(
        json!({
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": "hi"}]
            },
            "metadata": {
                "chio": {"targetSkillId": " echo "}
            }
        }),
        "SendMessage",
    ) {
        Ok(_) => panic!("expected padded targetSkillId to fail before lookup"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(
        message,
        "metadata.chio.targetSkillId must not include leading or trailing whitespace"
    );
}

#[test]
fn jsonrpc_send_message_single_skill() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut m = test_manifest();
            m.tools.truncate(1); // Only "echo"
            m
        }],
    )
    .test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    assert!(response.get("result").is_some());
    assert_eq!(
        response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn jsonrpc_send_message_rejects_empty_parts() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut m = test_manifest();
            m.tools.truncate(1);
            m
        }],
    )
    .test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": []
                }
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "message.parts must contain at least one part"
    );
}

#[test]
fn jsonrpc_send_message_with_skill_id() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": "echo"}
                }
            }
        }),
        &kernel,
        &execution,
    );
    assert!(response.get("result").is_some());
    assert_eq!(
        response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn jsonrpc_missing_skill_id_with_multiple_skills_errors() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    assert!(response.get("error").is_some());
}

#[test]
fn jsonrpc_unknown_method_returns_error() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
fn jsonrpc_send_rejects_non_object_params_before_skill_resolution() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
            "method": "message/send",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "message/send params must be an object"
    );
}

#[test]
fn jsonrpc_task_get_rejects_non_object_params_before_lookup() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "method": "task/get",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "task/get params must be an object"
    );
}

#[test]
fn jsonrpc_rejects_non_scalar_request_ids_before_method_dispatch() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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

    for invalid_id in [json!(true), json!({"nested": 1}), json!([1])] {
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
            "request id must be string, number, or null"
        );
    }
}

#[test]
fn jsonrpc_invalid_version_preserves_scalar_request_id() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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
            "method": "message/send",
            "params": {}
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["id"], "request-7");
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(response["error"]["message"], "invalid jsonrpc envelope");
}

#[test]
fn jsonrpc_send_rejects_non_object_params_before_dispatch() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut m = test_manifest();
            m.tools.truncate(1);
            m
        }],
    )
    .test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());

    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "message/send",
            "params": []
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "message/send params must be an object"
    );
}

#[test]
fn jsonrpc_send_reports_authoritative_path() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut m = test_manifest();
            m.tools.truncate(1);
            m
        }],
    )
    .test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());
    let response = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(
        response["result"]["metadata"]["chio"]["authoritative"].as_bool(),
        Some(true)
    );
    assert!(response["result"]["metadata"]["chio"]["receiptId"]
        .as_str()
        .is_some());
    assert_eq!(
        response["result"]["metadata"]["chio"]["lifecycle"]["messageStream"].as_str(),
        Some("deferred_task_poll")
    );
    assert_eq!(
        response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
        Some("a2a_authoritative")
    );
}

#[test]
fn jsonrpc_send_with_streaming_tool_collates_output_into_final_message() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(StreamingToolServer));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "id": 10,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(
        response["result"]["metadata"]["chio"]["streamProjection"].as_str(),
        Some("collated_final_message")
    );
    let parts = response["result"]["message"]["parts"]
        .as_array()
        .test_expect("stream response should contain parts");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0]["text"], "chunk-1");
    assert_eq!(parts[1]["text"], "chunk-2");
}

#[test]
fn jsonrpc_stream_creates_deferred_task_and_task_get_resolves_result() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(StreamingToolServer));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "id": 10,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(response["result"]["status"].as_str(), Some("working"));
    assert_eq!(
        response["result"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"].as_str(),
        Some("message/stream")
    );
    let task_id = response["result"]["id"]
        .as_str()
        .test_expect("message/stream should return task id")
        .to_string();
    assert_eq!(
        response["result"]["metadata"]["chio"]["receiptPending"].as_bool(),
        Some(true)
    );

    let resolved = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "task/get",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
    assert_eq!(
        resolved["result"]["metadata"]["chio"]["receiptId"]
            .as_str()
            .map(|value| !value.is_empty()),
        Some(true)
    );
    let parts = resolved["result"]["message"]["parts"]
        .as_array()
        .test_expect("resolved task should contain parts");
    assert_eq!(parts.len(), 2);
}

#[test]
fn jsonrpc_task_get_runtime_admission_denies_before_deferred_dispatch() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingStreamingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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

    let accepted = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(accepted["result"]["status"].as_str(), Some("working"));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let task_id = accepted["result"]["id"]
        .as_str()
        .test_expect("message/stream should return task id")
        .to_string();

    kernel.set_runtime_admission_hook(Arc::new(DenyingRuntimeAdmissionHook));
    let denied = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "task/get",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(denied["result"]["status"].as_str(), Some("failed"));
    assert_eq!(
        denied["result"]["statusMessage"].as_str(),
        Some("a2a edge runtime admission denied")
    );
    assert_eq!(
        denied["result"]["metadata"]
            .pointer("/chio/receipt/metadata/chio_runtime/failure_code")
            .and_then(Value::as_str),
        Some("a2a_edge_runtime_admission_denied")
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn jsonrpc_stream_notification_creates_task_without_response() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );

    assert!(response.is_notification());
    assert_eq!(edge.tasks.len(), 1);
}

#[test]
fn jsonrpc_task_get_retains_completed_deferred_task_result() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(StreamingToolServer));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    let task_id = created["result"]["id"].as_str().test_unwrap().to_string();

    let resolved = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "task/get",
            "params": { "taskId": task_id.clone() }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
    assert!(edge.tasks.contains_key(&task_id));

    let repeated = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "task/get",
            "params": { "taskId": task_id.clone() }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(repeated["result"]["status"].as_str(), Some("completed"));
    assert_eq!(
        repeated["result"]["metadata"]["chio"]["receiptId"],
        resolved["result"]["metadata"]["chio"]["receiptId"]
    );
}

#[test]
fn jsonrpc_task_get_rejects_empty_task_id_before_lookup() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "id": 32,
            "method": "task/get",
            "params": { "taskId": "" }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["message"],
        "task/get params.taskId must not be empty"
    );
}

#[test]
fn jsonrpc_task_id_params_reject_surrounding_whitespace_before_lookup() {
    let error = match ChioA2aEdge::parse_jsonrpc_task_id_params(
        &json!({ "taskId": " task-1 " }),
        "task/cancel",
    ) {
        Ok(_) => panic!("expected padded taskId to fail before lookup"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(
        message,
        "task/cancel params.taskId must not include leading or trailing whitespace"
    );
}

#[test]
fn jsonrpc_task_id_params_reject_control_characters_before_lookup() {
    let error = match ChioA2aEdge::parse_jsonrpc_task_id_params(
        &json!({ "taskId": "a2a-task-1\na2a-task-2" }),
        "task/get",
    ) {
        Ok(_) => panic!("expected control-character taskId to fail before lookup"),
        Err(error) => error,
    };
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(
        message,
        "task/get params.taskId must not include control characters"
    );
}

#[test]
fn jsonrpc_stream_rejects_deferred_task_map_over_cap() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["result"]["status"].as_str(), Some("working"));
    }

    let rejected = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 2_000,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );

    assert!(rejected["error"]["message"]
        .as_str()
        .test_unwrap()
        .contains("urn:chio:error:transport:task-capacity-exceeded"));
}

#[test]
fn jsonrpc_stream_rejects_padded_execution_agent_id_before_task_retention() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );

    assert_eq!(rejected["error"]["code"], -32602);
    assert_eq!(
        rejected["error"]["message"].as_str(),
        Some("A2A execution agent_id must not include leading or trailing whitespace")
    );
    assert!(edge.tasks.is_empty());
}

#[test]
fn jsonrpc_stream_capacity_counts_retained_terminal_deferred_tasks() {
    for terminal_status in [TaskStatus::Cancelled, TaskStatus::Completed] {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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

        for index in 0..MAX_DEFERRED_A2A_TASKS {
            let created = edge.handle_jsonrpc_value(
                json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "message/stream",
                    "params": {
                        "message": {
                            "role": "user",
                            "parts": [{"type": "text", "text": "start"}]
                        }
                    }
                }),
                &kernel,
                &execution,
            );
            assert_eq!(created["result"]["status"].as_str(), Some("working"));
            let task_id = created["result"]["id"]
                .as_str()
                .test_expect("message/stream should return task id")
                .to_string();
            let task = edge
                .tasks
                .get_mut(&task_id)
                .test_expect("stream task should be retained");
            task.response.status = terminal_status;
        }

        assert_eq!(edge.tasks.len(), MAX_DEFERRED_A2A_TASKS);

        let accepted = edge.handle_jsonrpc_value(
            json!({
                "jsonrpc": "2.0",
                "id": 3_000,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            accepted["error"]["message"],
            "urn:chio:error:transport:task-capacity-exceeded"
        );
        assert_eq!(edge.tasks.len(), MAX_DEFERRED_A2A_TASKS);
    }
}

#[test]
fn jsonrpc_task_cancel_marks_stream_task_cancelled() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "id": 12,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    let task_id = response["result"]["id"].as_str().test_unwrap().to_string();

    let cancelled = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "task/cancel",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));
    assert_eq!(
        cancelled["result"]["metadata"]["chio"]["decision"].as_str(),
        Some("cancelled")
    );

    let cancelled_again = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "task/cancel",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(
        cancelled_again["result"]["status"].as_str(),
        Some("cancelled")
    );
    assert_eq!(
        cancelled_again["result"]["metadata"]["chio"]["decision"].as_str(),
        Some("cancelled")
    );
}

#[test]
fn complete_task_preserves_cancelled_deferred_task() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(StreamingToolServer));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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
            "id": 15,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "start"}]
                }
            }
        }),
        &kernel,
        &execution,
    );
    let task_id = created["result"]["id"].as_str().test_unwrap().to_string();

    let cancelled = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "task/cancel",
            "params": {
                "taskId": task_id.clone()
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));

    let completed_after_cancel = edge.complete_task(&task_id, &kernel, &execution, json!(17));
    assert_eq!(
        completed_after_cancel["result"]["status"].as_str(),
        Some("cancelled")
    );
    assert_eq!(
        completed_after_cancel["result"]["metadata"]["chio"]["decision"].as_str(),
        Some("cancelled")
    );

    let repeated = edge.handle_jsonrpc_value(
        json!({
            "jsonrpc": "2.0",
            "id": 18,
            "method": "task/get",
            "params": {
                "taskId": task_id
            }
        }),
        &kernel,
        &execution,
    );
    assert_eq!(repeated["result"]["status"].as_str(), Some("cancelled"));
}

#[test]
fn authoritative_send_uses_protocol_aware_target_binding() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![mcp_target_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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

    let response = edge
        .handle_send_message(
            "echo",
            &SendMessageRequest {
                message: A2aMessage {
                    role: "user".to_string(),
                    parts: vec![A2aPart::Data {
                        data: json!({"message": "hello"}),
                    }],
                    metadata: None,
                },
                metadata: None,
            },
            &kernel,
            &execution,
        )
        .test_unwrap();

    let metadata = response.metadata.test_unwrap();
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("mcp")
    );
    assert_eq!(
        metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata["chio"]["bridge"]["route"]["selectedProtocols"],
        json!(["a2a", "mcp", "native"])
    );
}

#[test]
fn authoritative_send_supports_openai_target_binding() {
    let mut edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![openai_target_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
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

    let response = edge
        .handle_send_message(
            "echo",
            &SendMessageRequest {
                message: A2aMessage {
                    role: "user".to_string(),
                    parts: vec![A2aPart::Data {
                        data: json!({"message": "hello"}),
                    }],
                    metadata: None,
                },
                metadata: None,
            },
            &kernel,
            &execution,
        )
        .test_unwrap();

    let metadata = response.metadata.test_unwrap();
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("open_ai")
    );
    assert_eq!(
        metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
        Some(true)
    );
}

#[test]
fn invalid_target_protocol_metadata_fails_closed() {
    let error = match ChioA2aEdge::new(A2aEdgeConfig::default(), vec![invalid_target_manifest()]) {
        Ok(_) => panic!("expected invalid target protocol metadata to fail"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("unsupported x-chio-target-protocol value"));
}
