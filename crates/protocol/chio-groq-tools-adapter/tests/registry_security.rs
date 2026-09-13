use std::cell::Cell;
use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::Keypair;
use chio_groq_tools_adapter::{GroqAdapter, GroqAdapterConfig, GroqAdapterError, MockTransport};
use chio_manifest::{
    RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_test_support::prelude::*;
use chio_tool_call_fabric::{ProviderRequest, ReceiptId, VerdictResult};
use serde_json::json;

const SERVER_ID: &str = "groq-security";
const TOOL_NAME: &str = "get_weather";

fn signed_registry() -> (
    GroqAdapterConfig,
    VerifiedManifestRegistry,
    ToolFlowDeclaration,
) {
    let signer = Keypair::from_seed(&[61; 32]);
    let flow = ToolFlowDeclaration::public_egress();
    let config = GroqAdapterConfig::new(
        SERVER_ID,
        "Groq security",
        "1.0.0",
        signer.public_key().to_hex(),
        "project-security",
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
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "call-security",
                        "type": "function",
                        "function": {"name": tool_name, "arguments": "{}"}
                    }]
                }
            }]
        }))
        .test_unwrap(),
    )
}

fn stream_payload(tool_name: &str) -> Vec<u8> {
    let chunk = json!({
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "id": "call-security-stream",
                    "type": "function",
                    "function": {"name": tool_name, "arguments": "{}"}
                }]
            }
        }]
    });
    let mut stream = b"data: ".to_vec();
    stream.extend_from_slice(&serde_json::to_vec(&chunk).test_unwrap());
    stream.extend_from_slice(b"\n\ndata: [DONE]\n\n");
    stream
}

fn allow() -> VerdictResult {
    VerdictResult::Allow {
        redactions: Vec::new(),
        receipt_id: ReceiptId("receipt-groq-security".to_string()),
    }
}

#[test]
fn registry_bound_stream_preserves_exact_canonical_flow_bytes() {
    let (config, registry, expected_flow) = signed_registry();
    let adapter = GroqAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
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
    let adapter = GroqAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
        .test_unwrap();

    let error = adapter
        .lift_batch(batch_payload("unknown_tool"))
        .test_expect_err("unknown bound tool must fail closed");

    assert!(error
        .to_string()
        .contains("admitted security sidecar is missing for Groq tool `unknown_tool`"));
}

#[test]
fn registry_bound_constructor_rejects_missing_server() {
    let (mut config, registry, _) = signed_registry();
    config.server_id = "missing-groq".to_string();

    let error = GroqAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
        .err()
        .test_expect("missing server must fail closed");

    assert!(matches!(
        error,
        GroqAdapterError::RegistryManifestUnavailable { .. }
    ));
}

#[test]
fn registry_bound_constructor_rejects_config_mismatch() {
    let (mut config, registry, _) = signed_registry();
    config.server_version = "2.0.0".to_string();

    let error = GroqAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
        .err()
        .test_expect("config mismatch must fail closed");

    assert!(matches!(
        error,
        GroqAdapterError::ConfigManifestMismatch { .. }
    ));
}

#[test]
fn raw_projection_stream_rejects_before_evaluator() {
    let (config, _, _) = signed_registry();
    let adapter = GroqAdapter::new(config, Arc::new(MockTransport::new()));
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
    let adapter = GroqAdapter::new(config, Arc::new(MockTransport::new()));

    let invocations = adapter.lift_batch(batch_payload(TOOL_NAME)).test_unwrap();

    assert_eq!(invocations.len(), 1);
    assert!(invocations[0].bridge_security.is_none());
}
