use super::*;
use chio_core::Keypair;
use chio_manifest::{
    RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use serde_json::json;

fn config() -> OllamaAdapterConfig {
    OllamaAdapterConfig::new(
        "ollama-1",
        "Ollama Chat",
        "0.1.0",
        "deadbeef",
        "local_chio_demo",
    )
}

fn config_with_api_version(api_version: &str) -> OllamaAdapterConfig {
    let mut cfg = config();
    cfg.api_version = api_version.to_string();
    cfg
}

fn mock() -> Arc<transport::MockTransport> {
    Arc::new(transport::MockTransport::new("mock://ollama"))
}

fn adapter() -> OllamaAdapter {
    OllamaAdapter::new(config(), mock())
}

fn admitted_registry(
    tool_name: &str,
) -> (
    OllamaAdapterConfig,
    VerifiedManifestRegistry,
    ToolFlowDeclaration,
) {
    let signer = Keypair::from_seed(&[61; 32]);
    let config = OllamaAdapterConfig::new(
        "ollama-1",
        "Ollama Chat",
        "0.1.0",
        signer.public_key().to_hex(),
        "local_chio_demo",
    );
    let flow = ToolFlowDeclaration::public_egress();
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: config.server_id.clone(),
        name: config.server_name.clone(),
        description: None,
        version: config.server_version.clone(),
        tools: vec![ToolDefinition {
            name: tool_name.to_string(),
            description: "Admitted Ollama tool".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: false,
                requires_approval: false,
                estimated_duration_ms: None,
            },
            latency_hint: None,
            flow: Some(flow.clone()),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer).unwrap();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap();
    (config, registry, flow)
}

fn admitted_adapter(tool_name: &str) -> (OllamaAdapter, ToolFlowDeclaration) {
    let (config, registry, flow) = admitted_registry(tool_name);
    let adapter = OllamaAdapter::new_with_registry(config, mock(), &registry).unwrap();
    (adapter, flow)
}

fn tool_call_payload() -> Value {
    json!({
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}
            ]
        }
    })
}

fn tool_call_stream() -> Vec<u8> {
    let mut ndjson = serde_json::to_vec(&tool_call_payload()).unwrap();
    ndjson.push(b'\n');
    ndjson
}

fn raw_payload(value: Value) -> ProviderRequest {
    ProviderRequest(serde_json::to_vec(&value).unwrap())
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_api_pin".into()),
    }
}

fn assert_api_version_drift(error: ProviderError) {
    match error {
        ProviderError::Malformed(message) => {
            assert!(message.contains("Ollama adapter supports only API version 2025-04"));
            assert!(message.contains("configured 2024-12"));
        }
        other => panic!("expected Malformed API version drift, got {other:?}"),
    }
}

#[test]
fn config_pins_api_version() {
    let cfg = config();
    assert_eq!(cfg.api_version, OLLAMA_API_VERSION);
    assert_eq!(cfg.api_version, "2025-04");
}

#[test]
fn adapter_reports_provider_and_pin() {
    let adapter = adapter();
    assert_eq!(adapter.provider(), ProviderId::Ollama);
    assert_eq!(adapter.api_version(), "2025-04");
}

#[test]
fn registry_bound_lift_preserves_exact_flow_sidecar() {
    let (adapter, expected_flow) = admitted_adapter("get_weather");
    let invocation = adapter
        .lift_batch(raw_payload(tool_call_payload()))
        .unwrap()
        .remove(0);

    let security = invocation
        .bridge_security
        .as_ref()
        .expect("registry-bound lift retains security");
    assert!(security.has_registry_coordinates());
    assert_eq!(
        canonical_json_bytes(security.flow().expect("flow sidecar")).unwrap(),
        canonical_json_bytes(&expected_flow).unwrap()
    );
}

#[test]
fn registry_bound_constructor_rejects_missing_server() {
    let (mut config, registry, _) = admitted_registry("get_weather");
    config.server_id = "missing-ollama".to_string();

    let error = match OllamaAdapter::new_with_registry(config, mock(), &registry) {
        Ok(_) => panic!("missing admitted server must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        OllamaAdapterError::RegistryManifestUnavailable { .. }
    ));
}

#[test]
fn registry_bound_constructor_rejects_config_mismatch() {
    let (mut config, registry, _) = admitted_registry("get_weather");
    config.server_name = "Other Ollama".to_string();

    let error = match OllamaAdapter::new_with_registry(config, mock(), &registry) {
        Ok(_) => panic!("config identity mismatch must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        OllamaAdapterError::ConfigManifestMismatch { .. }
    ));
}

#[test]
fn registry_bound_lift_rejects_unknown_tool_sidecar() {
    let (adapter, _) = admitted_adapter("get_weather");
    let payload = json!({
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": "send_email", "arguments": {}}}
            ]
        }
    });

    let error = adapter
        .lift_batch(raw_payload(payload))
        .expect_err("unknown tool must not inherit an admitted sidecar");

    assert!(error.to_string().contains(
        "registry-bound Ollama lift has no admitted security sidecar for tool `send_email`"
    ));
}

#[test]
fn raw_projection_cannot_enter_stream_evaluator() {
    let adapter = adapter();
    let evaluated = std::cell::Cell::new(false);

    let error = adapter
        .gate_sse_stream(&tool_call_stream(), |_invocation| {
            evaluated.set(true);
            Ok(allow_verdict())
        })
        .expect_err("raw projection must not be execution-ready");

    assert!(error
        .to_string()
        .contains("requires a registry-admitted security sidecar"));
    assert!(!evaluated.get());
}

#[tokio::test]
async fn chat_rejects_api_version_drift_before_transport_call() {
    let mock = mock();
    mock.push_json_response(serde_json::to_vec(&tool_call_payload()).unwrap());
    let adapter = OllamaAdapter::new(config_with_api_version("2024-12"), mock.clone());

    let err = adapter
        .chat(b"{\"model\":\"llama3.2:1b\",\"stream\":false}")
        .await
        .expect_err("drifted Ollama API version must fail before transport");

    assert_api_version_drift(err);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn chat_stream_rejects_api_version_drift_before_transport_call() {
    let mock = mock();
    mock.push_response(chio_provider_adapter_core::http::HttpResponse::new(
        200,
        tool_call_stream(),
        Some("application/x-ndjson".to_string()),
    ));
    let adapter = OllamaAdapter::new(config_with_api_version("2024-12"), mock.clone());

    let err = adapter
        .chat_stream(b"{\"stream\":true}", |_invocation| Ok(allow_verdict()))
        .await
        .expect_err("drifted Ollama API version must fail before stream transport");

    assert_api_version_drift(err);
    assert!(mock.calls().is_empty());
}

#[test]
fn lift_batch_rejects_api_version_drift_before_provenance_stamp() {
    let adapter = OllamaAdapter::new(config_with_api_version("2024-12"), mock());

    let err = adapter
        .lift_batch(raw_payload(tool_call_payload()))
        .expect_err("drifted Ollama API version must fail before provenance stamping");

    assert_api_version_drift(err);
}

#[test]
fn gate_sse_stream_rejects_api_version_drift_before_evaluator() {
    let adapter = OllamaAdapter::new(config_with_api_version("2024-12"), mock());
    let evaluated = std::cell::Cell::new(false);

    let err = adapter
        .gate_sse_stream(&tool_call_stream(), |_invocation| {
            evaluated.set(true);
            Ok(allow_verdict())
        })
        .expect_err("drifted Ollama API version must fail before stream evaluation");

    assert_api_version_drift(err);
    assert!(!evaluated.get());
}

#[test]
fn invocation_from_tool_call_rejects_api_version_drift_before_provenance_stamp() {
    let adapter = OllamaAdapter::new(config_with_api_version("2024-12"), mock());
    let call = ToolCallPart::new("get_weather", json!({"city": "Paris"}));

    let err = adapter
        .invocation_from_tool_call(0, &call)
        .expect_err("drifted Ollama API version must fail before provenance stamping");

    assert_api_version_drift(err);
}

#[test]
fn lower_tool_message_rejects_api_version_drift() {
    let adapter = OllamaAdapter::new(config_with_api_version("2024-12"), mock());

    let err = adapter
        .lower_tool_message(
            "get_weather",
            allow_verdict(),
            ToolResult(b"{\"temp\":18}".to_vec()),
        )
        .expect_err("drifted Ollama API version must fail before lowering");

    assert_api_version_drift(err);
}

#[tokio::test]
async fn chat_posts_to_api_chat_and_lifts_tool_calls() {
    let response = json!({
        "model": "llama3.2:1b",
        "done": true,
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}
            ]
        }
    });
    let mock = mock();
    mock.push_json_response(serde_json::to_vec(&response).unwrap());
    let adapter = OllamaAdapter::new(config(), mock.clone());

    let request = serde_json::to_vec(&json!({
        "model": "llama3.2:1b",
        "stream": false,
        "messages": [{"role": "user", "content": "weather in Paris?"}]
    }))
    .unwrap();
    let invocations = adapter.chat(&request).await.unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provider, ProviderId::Ollama);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, transport::OLLAMA_CHAT_PATH);
    assert_eq!(calls[0].body, request);
}

#[tokio::test]
async fn chat_maps_upstream_5xx_to_provider_error() {
    let mock = mock();
    mock.push_response(chio_provider_adapter_core::http::HttpResponse::new(
        503,
        b"model not loaded".to_vec(),
        Some("application/json".to_string()),
    ));
    let adapter = OllamaAdapter::new(config(), mock);
    let error = adapter.chat(b"{}").await.unwrap_err();
    assert!(matches!(
        error,
        ProviderError::Upstream5xx { status: 503, .. }
    ));
}

#[tokio::test]
async fn chat_stream_gates_ndjson_tool_calls() {
    let ndjson = concat!(
        "{\"model\":\"llama3.2:1b\",\"message\":{\"role\":\"assistant\",\"content\":\"\"}}\n",
        "{\"model\":\"llama3.2:1b\",\"done\":true,\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"get_weather\",\"arguments\":{\"city\":\"Paris\"}}}]}}\n"
    );
    let mock = mock();
    mock.push_response(chio_provider_adapter_core::http::HttpResponse::new(
        200,
        ndjson.as_bytes().to_vec(),
        Some("application/x-ndjson".to_string()),
    ));
    let (config, registry, _) = admitted_registry("get_weather");
    let adapter = OllamaAdapter::new_with_registry(config, mock.clone(), &registry).unwrap();

    let gated = adapter
        .chat_stream(b"{\"stream\":true}", |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
            })
        })
        .await
        .unwrap();
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.verdicts.len(), 1);
    assert_eq!(
        mock.calls()[0].kind,
        chio_provider_adapter_core::http::CallKind::Ndjson
    );
}

#[test]
fn lift_batch_extracts_tool_calls() {
    let adapter = adapter();
    let payload = json!({
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}
            ]
        }
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let invocations = adapter.lift_batch(raw).unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provider, ProviderId::Ollama);
}

#[test]
fn lift_batch_extracts_tool_calls_from_string_body_envelope() {
    let adapter = adapter();
    let payload = json!({
        "body": r#"{"message":{"role":"assistant","tool_calls":[{"function":{"name":"get_weather","arguments":{"city":"Paris"}}}]}}"#
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());

    let invocations = adapter.lift_batch(raw).unwrap();

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provider, ProviderId::Ollama);
}

#[test]
fn lift_batch_classifies_policy_refusal_as_content_policy() {
    let adapter = adapter();
    let payload = json!({
        "done_reason": "stop",
        "policy": "refusal"
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();

    assert!(matches!(err, ProviderError::ContentPolicy(_)));
}

#[test]
fn gate_sse_stream_classifies_policy_refusal_before_forwarding() {
    let adapter = adapter();
    let ndjson = br#"{"done":true,"done_reason":"stop","policy":"refusal"}
"#;
    let err = adapter
        .gate_sse_stream(ndjson, |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_refusal".into()),
            })
        })
        .unwrap_err();

    assert!(matches!(err, ProviderError::ContentPolicy(_)));
}

#[test]
fn lift_batch_rejects_tool_call_name_with_surrounding_whitespace() {
    let adapter = adapter();
    let payload = json!({
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": " get_weather ", "arguments": {"city": "Paris"}}}
            ]
        }
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();

    assert!(err.to_string().contains("surrounding whitespace"));
}

#[test]
fn lift_batch_rejects_malformed_envelope_before_outer_tool_calls() {
    let adapter = adapter();
    let payload = json!({
        "body": 42,
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": "unsafe_outer", "arguments": {"source": "outer"}}}
            ]
        }
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());

    let err = adapter.lift_batch(raw).unwrap_err();

    match err {
        ProviderError::Malformed(message) => {
            assert!(message.contains("envelope field `body`"));
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn lift_batch_rejects_payload_without_tool_calls() {
    let adapter = adapter();
    let payload = json!({"message": {"role": "assistant", "content": "no tools"}});
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();
    match err {
        ProviderError::Malformed(_) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn lower_tool_message_allow() {
    let adapter = adapter();
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_demo".into()),
    };
    let result = ToolResult(b"{\"temp\":18}".to_vec());
    let msg = adapter
        .lower_tool_message("get_weather", verdict, result)
        .unwrap();
    assert_eq!(msg.role, "tool");
    assert_eq!(msg.name, "get_weather");
    assert!(msg.content.contains("\"temp\""));
}

#[test]
fn lower_allow_tool_message_helper_applies_redactions_and_canonicalizes() {
    let msg = lower_allow_tool_message(
        "get_weather",
        ToolResult(br#"{"token":"secret","ok":true}"#.to_vec()),
        &[Redaction {
            path: "/token".to_string(),
            replacement: "[redacted]".to_string(),
        }],
    )
    .unwrap();

    assert_eq!(msg.role, "tool");
    assert_eq!(msg.name, "get_weather");
    assert_eq!(msg.content, r#"{"ok":true,"token":"[redacted]"}"#);
}
