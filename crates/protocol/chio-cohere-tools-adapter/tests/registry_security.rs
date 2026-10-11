use std::cell::Cell;
use std::sync::Arc;

use chio_cohere_tools_adapter::{
    CohereAdapter, CohereAdapterConfig, CohereAdapterError, MockTransport,
};
use chio_core::canonical::canonical_json_bytes;
use chio_core::Keypair;
use chio_manifest::{
    RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_test_support::prelude::*;
use chio_tool_call_fabric::{ProviderRequest, ReceiptId, VerdictResult};
use serde_json::json;

#[path = "registry_security/delta_identity.rs"]
mod delta_identity;
#[path = "registry_security/lifecycle_payload.rs"]
mod lifecycle_payload;
#[path = "registry_security/provider_contract.rs"]
mod provider_contract;
#[path = "registry_security/terminal_payload.rs"]
mod terminal_payload;

const SERVER_ID: &str = "cohere-security";
const TOOL_NAME: &str = "get_weather";

fn signed_registry() -> (
    CohereAdapterConfig,
    VerifiedManifestRegistry,
    ToolFlowDeclaration,
) {
    let signer = Keypair::from_seed(&[63; 32]);
    let flow = ToolFlowDeclaration::public_egress();
    let config = CohereAdapterConfig::new(
        SERVER_ID,
        "Cohere security",
        "1.0.0",
        signer.public_key().to_hex(),
        "org-security",
    );
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: config.server_id.clone(),
        name: config.server_name.clone(),
        description: None,
        version: config.server_version.clone(),
        tools: vec![ToolDefinition {
            name: TOOL_NAME.to_string(),
            description: "Read weather".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: Some(flow.clone()),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: config.public_key.clone(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer).test_unwrap();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .test_unwrap();
    (config, registry, flow)
}

fn batch_payload(tool_name: &str) -> ProviderRequest {
    ProviderRequest(
        serde_json::to_vec(&json!({
            "message": {
                "tool_calls": [{
                    "id": "call-security",
                    "type": "function",
                    "function": {"name": tool_name, "arguments": "{}"}
                }]
            }
        }))
        .test_unwrap(),
    )
}

fn stream_payload(tool_name: &str) -> Vec<u8> {
    let data = json!({
        "tool_call": {
            "id": "call-security-stream",
            "type": "function",
            "function": {"name": tool_name, "arguments": "{}"}
        }
    });
    let mut stream = b"event: tool-call-end\ndata: ".to_vec();
    stream.extend_from_slice(&serde_json::to_vec(&data).test_unwrap());
    stream.extend_from_slice(b"\n\n");
    stream
}

fn allow() -> VerdictResult {
    VerdictResult::Allow {
        redactions: Vec::new(),
        receipt_id: ReceiptId("receipt-cohere-security".to_string()),
    }
}

#[test]
fn registry_bound_stream_preserves_exact_canonical_flow_bytes() {
    let (config, registry, expected_flow) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    let mut observed_flow = None;

    let gated = adapter
        .gate_sse_stream(&stream_payload(TOOL_NAME), |invocation| {
            let security = invocation.bridge_security.as_ref().test_unwrap();
            assert!(security.has_registry_coordinates());
            observed_flow = Some(canonical_json_bytes(security.flow().test_unwrap()).test_unwrap());
            Ok(allow())
        })
        .test_unwrap();

    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(
        observed_flow.test_unwrap(),
        canonical_json_bytes(&expected_flow).test_unwrap()
    );
}

#[test]
fn registry_bound_lift_rejects_unknown_tool_sidecar() {
    let (config, registry, _) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();

    let error = adapter
        .lift_batch(batch_payload("unknown_tool"))
        .test_expect_err("unknown bound tool must fail closed");

    assert!(error
        .to_string()
        .contains("admitted security sidecar is missing for Cohere tool `unknown_tool`"));
}

#[test]
fn registry_bound_constructor_rejects_missing_server() {
    let (mut config, registry, _) = signed_registry();
    config.server_id = "missing-cohere".to_string();

    let error = CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
        .err()
        .test_expect("missing server must fail closed");

    assert!(matches!(
        error,
        CohereAdapterError::RegistryManifestUnavailable { .. }
    ));
}

#[test]
fn registry_bound_constructor_rejects_config_mismatch() {
    let (mut config, registry, _) = signed_registry();
    config.server_name = "Other Cohere".to_string();

    let error = CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
        .err()
        .test_expect("config mismatch must fail closed");

    assert!(matches!(
        error,
        CohereAdapterError::ConfigManifestMismatch { .. }
    ));
}

#[test]
fn raw_projection_stream_rejects_before_evaluator() {
    let (config, _, _) = signed_registry();
    let adapter = CohereAdapter::new(config, Arc::new(MockTransport::new()));
    let evaluated = Cell::new(false);

    let error = adapter
        .gate_sse_stream(&stream_payload(TOOL_NAME), |_| {
            evaluated.set(true);
            Ok(allow())
        })
        .test_expect_err("raw projection must not enter streaming authorization");

    assert!(error
        .to_string()
        .contains("requires a registry-admitted security sidecar"));
    assert!(!evaluated.get());
}

#[test]
fn raw_batch_projection_remains_non_authoritative() {
    let (config, _, _) = signed_registry();
    let adapter = CohereAdapter::new(config, Arc::new(MockTransport::new()));

    let invocations = adapter.lift_batch(batch_payload(TOOL_NAME)).test_unwrap();

    assert_eq!(invocations.len(), 1);
    assert!(invocations[0].bridge_security.is_none());
}

fn gate(raw: &[u8]) -> Result<usize, chio_tool_call_fabric::ProviderError> {
    let (config, registry, _) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    adapter
        .gate_sse_stream(raw, |_| Ok(allow()))
        .map(|gated| gated.invocations.len())
}

fn frame(event: Option<&str>, data: serde_json::Value) -> String {
    match event {
        Some(event) => format!("event: {event}\ndata: {data}\n\n"),
        None => format!("data: {data}\n\n"),
    }
}

fn start_frame(arguments: &str) -> String {
    frame(
        Some("tool-call-start"),
        json!({"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{
            "id":"call-assembled","type":"function",
            "function":{"name":TOOL_NAME,"arguments":arguments}}}}}),
    )
}

fn delta_frame(arguments: &str) -> String {
    frame(
        Some("tool-call-delta"),
        json!({"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{
            "function":{"arguments":arguments}}}}}),
    )
}

#[test]
fn plain_json_chat_body_with_tool_calls_fails_closed() {
    let body = serde_json::to_vec(&json!({
        "id": "chat-1",
        "message": {"tool_calls": [{"id":"call-json","type":"function",
            "function":{"name":TOOL_NAME,"arguments":"{}"}}]}
    }))
    .test_unwrap();
    assert!(gate(&body).is_err());
}

#[test]
fn data_only_tool_call_end_frame_is_evaluated() {
    let raw = frame(
        None,
        json!({"type":"tool-call-end","tool_call":{"id":"call-data-only","type":"function",
            "function":{"name":TOOL_NAME,"arguments":"{}"}}}),
    );
    assert_eq!(gate(raw.as_bytes()).test_unwrap(), 1);
}

#[test]
fn start_and_delta_without_end_fails_closed() {
    let raw = format!("{}{}", start_frame(""), delta_frame("{}"));
    assert!(gate(raw.as_bytes()).is_err());
}

#[test]
fn start_delta_end_stream_is_assembled_and_evaluated() {
    let raw = format!(
        "{}{}{}{}",
        start_frame(""),
        delta_frame("{\"city\":"),
        delta_frame("\"Paris\"}"),
        frame(
            Some("tool-call-end"),
            json!({"type":"tool-call-end","index":0})
        ),
    );
    assert_eq!(gate(raw.as_bytes()).test_unwrap(), 1);
}

#[test]
fn unknown_event_fails_closed() {
    let raw = frame(Some("tool-call-future"), json!({"type":"tool-call-future"}));
    assert!(gate(raw.as_bytes()).is_err());
}

#[test]
fn tool_calls_outside_tool_call_frames_fail_closed() {
    let raw = frame(
        Some("content-delta"),
        json!({"type":"content-delta","delta":{"message":{"tool_calls":{"id":"call-smuggled",
            "type":"function","function":{"name":TOOL_NAME,"arguments":"{}"}}}}}),
    );
    assert!(gate(raw.as_bytes()).is_err());
}

#[test]
fn stream_that_opens_with_message_start_must_reach_message_end() {
    let raw = frame(
        Some("message-start"),
        json!({"type":"message-start","id":"msg-1"}),
    );
    assert!(gate(raw.as_bytes()).is_err());
    let complete = format!(
        "{}{}",
        raw,
        frame(
            Some("message-end"),
            json!({"type":"message-end","delta":{"finish_reason":"COMPLETE"}})
        )
    );
    assert_eq!(gate(complete.as_bytes()).test_unwrap(), 0);
}
