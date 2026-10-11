use super::*;
use chio_core::crypto::Keypair;
use chio_manifest::{
    RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use serde_json::Value;

pub(super) fn admitted_adapter() -> (OpenAiAdapter, ToolFlowDeclaration) {
    let signer = Keypair::from_seed(&[54; 32]);
    let flow = ToolFlowDeclaration::public_egress();
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
        server_id: "openai-stream-bound".into(),
        name: "OpenAI stream fixture".into(),
        description: None,
        version: "1".into(),
        tools: vec![ToolDefinition {
            name: "get_weather".into(),
            description: "Admitted weather".into(),
            input_schema: json!({"type":"object"}),
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
        server_tools: vec![],
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer).unwrap();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap();
    (
        OpenAiAdapter::new_with_registry(
            OpenAiAdapterConfig::new("org-stream-bound"),
            "openai-stream-bound",
            &registry,
        )
        .unwrap(),
        flow,
    )
}

fn item(id: &str) -> Value {
    json!({"type":"function_call","id":format!("item-{id}"),"call_id":id,
        "name":"get_weather","arguments":"{\"city\":\"London\"}"})
}

fn prefix(ids: &[&str]) -> String {
    let mut stream = String::new();
    for (index, id) in ids.iter().enumerate() {
        let mut start = item(id);
        start["arguments"] = json!("");
        stream.push_str(&sse(&[
            ("response.output_item.added", json!({"type":"response.output_item.added","output_index":index,"item":start})),
            ("response.function_call_arguments.done", json!({"type":"response.function_call_arguments.done","output_index":index,"item_id":format!("item-{id}"),"arguments":"{\"city\":\"London\"}"})),
            ("response.output_item.done", json!({"type":"response.output_item.done","output_index":index,"item":item(id)})),
        ]));
    }
    stream
}

fn completed(output: Option<Value>) -> String {
    let mut response = json!({"id":"response-bound"});
    if let Some(output) = output {
        response["output"] = output;
    }
    sse(&[(
        "response.completed",
        json!({"type":"response.completed","response":response}),
    )])
}

fn checked_allow(
    invocation: &chio_tool_call_fabric::ToolInvocation,
    flow: &ToolFlowDeclaration,
) -> VerdictResult {
    let security = invocation.bridge_security.as_ref().unwrap();
    assert!(security.has_registry_coordinates());
    assert_eq!(
        canonical_json_bytes(security.flow().unwrap()).unwrap(),
        canonical_json_bytes(flow).unwrap()
    );
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(
        invocation.arguments,
        canonical_json_bytes(&json!({"city":"London"})).unwrap()
    );
    allow_verdict()
}

#[test]
fn supplied_empty_final_output_cannot_erase_an_approved_call() {
    let (adapter, flow) = admitted_adapter();
    let raw = prefix(&["a"]) + &completed(Some(json!([])));
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |invocation| {
        evaluated += 1;
        Ok(checked_allow(invocation, &flow))
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "approved call disappeared: {result:?}"
    );
    assert_eq!(evaluated, 1);
}

#[test]
fn supplied_partial_final_output_cannot_omit_one_of_two_approved_calls() {
    let (adapter, flow) = admitted_adapter();
    let raw = prefix(&["a", "b"]) + &completed(Some(json!([item("a")])));
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |invocation| {
        evaluated += 1;
        Ok(checked_allow(invocation, &flow))
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "approved set omitted b: {result:?}"
    );
    assert_eq!(evaluated, 2);
}

#[test]
fn repeated_streamed_call_id_cannot_be_approved_twice() {
    let (adapter, flow) = admitted_adapter();
    let raw = prefix(&["a", "a"]) + &completed(Some(json!([item("a")])));
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |invocation| {
        evaluated += 1;
        Ok(checked_allow(invocation, &flow))
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "duplicate approved ID was forwarded: {result:?}"
    );
    assert_eq!(evaluated, 1, "duplicate reached a second evaluation");
}

#[test]
fn repeated_completed_event_cannot_release_a_second_final_copy() {
    let (adapter, flow) = admitted_adapter();
    let end = completed(Some(json!([item("a")])));
    let raw = prefix(&["a"]) + &end + &end;
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |invocation| {
        evaluated += 1;
        Ok(checked_allow(invocation, &flow))
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "terminal completion was repeated: {result:?}"
    );
    assert_eq!(evaluated, 1);
}

#[test]
fn full_final_set_and_legacy_absent_output_keep_exact_bytes_and_sidecars() {
    for output in [
        None,
        Some(
            json!([item("a"), item("b"), {"type":"message","id":"message-note","role":"assistant","content":[]}]),
        ),
    ] {
        let (adapter, flow) = admitted_adapter();
        let raw =
            prefix(&["a", "b"]) + &completed(output) + ": healthy comment\n\ndata: [DONE]\n\n";
        let mut evaluated = Vec::new();
        let gated = adapter
            .gate_sse_stream(raw.as_bytes(), |invocation| {
                evaluated.push(invocation.provenance.request_id.clone());
                Ok(checked_allow(invocation, &flow))
            })
            .unwrap();
        assert_eq!(gated.bytes, raw.as_bytes());
        assert_eq!(evaluated, vec!["a", "b"]);
        assert_eq!(gated.invocations.len(), 2);
        assert_eq!(gated.verdicts, vec![allow_verdict(), allow_verdict()]);
    }
}
