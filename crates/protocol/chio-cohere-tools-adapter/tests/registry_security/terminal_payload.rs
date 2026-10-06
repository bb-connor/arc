use super::*;
use chio_tool_call_fabric::ProviderError;
use serde_json::Value;

fn call(id: &str, name: &str, arguments: &str) -> Value {
    json!({"id":id,"type":"function","function":{"name":name,"arguments":arguments}})
}

fn assembled(end: Value) -> Vec<u8> {
    format!("{}{}", start_frame("{}"), frame(Some("tool-call-end"), end)).into_bytes()
}

fn preserves(raw: Vec<u8>, arguments: Value) {
    let (config, registry, flow) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    let evaluated = Cell::new(0);
    let gated = adapter
        .gate_sse_stream(&raw, |invocation| {
            evaluated.set(evaluated.get() + 1);
            let security = invocation.bridge_security.as_ref().test_unwrap();
            assert!(security.has_registry_coordinates());
            assert_eq!(
                canonical_json_bytes(security.flow().test_unwrap()).test_unwrap(),
                canonical_json_bytes(&flow).test_unwrap()
            );
            assert_eq!(invocation.tool_name, TOOL_NAME);
            assert_eq!(
                invocation.arguments,
                canonical_json_bytes(&arguments).test_unwrap()
            );
            Ok(allow())
        })
        .test_unwrap();
    assert_eq!(gated.bytes, raw);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.verdicts, vec![allow()]);
    assert_eq!(evaluated.get(), 1);
}

#[test]
fn terminal_stream_style_or_extra_tool_payload_cannot_bypass_assembled_call() {
    let accepted = call("call-assembled", TOOL_NAME, "{}");
    let hidden = call("call-hidden", "unevaluated_tool", "{\"secret\":true}");
    let ends = [
        json!({"type":"tool-call-end","index":0,"delta":{"message":{"tool_calls":hidden}}}),
        json!({"type":"tool-call-end","index":0,"tool_call":accepted,
            "delta":{"message":{"tool_calls":[hidden]}}}),
        json!({"type":"tool-call-end","index":0,"tool_call":accepted,
            "delta":{"tool_call":hidden}}),
        json!({"type":"tool-call-end","index":0,"tool_call":accepted,
            "extra":{"tool_call":hidden}}),
    ];
    for end in ends {
        let raw = assembled(end);
        let (config, registry, _) = signed_registry();
        let adapter =
            CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
                .test_unwrap();
        let evaluated = Cell::new(0);
        let result = adapter.gate_sse_stream(&raw, |_| {
            evaluated.set(evaluated.get() + 1);
            Ok(allow())
        });
        assert!(
            matches!(result, Err(ProviderError::Malformed(_))),
            "terminal tool payload bypassed the assembled call: {result:?}"
        );
        assert_eq!(evaluated.get(), 0, "terminal mismatch reached evaluation");
    }
}

#[test]
fn index_only_terminal_keeps_exact_bytes_and_signed_registry_flow() {
    let raw = format!(
        "{}{}{}{}",
        start_frame(""),
        delta_frame("{\"city\":"),
        delta_frame("\"Paris\"}"),
        frame(
            Some("tool-call-end"),
            json!({"type":"tool-call-end","index":0})
        )
    )
    .into_bytes();
    preserves(raw, json!({"city":"Paris"}));
}

#[test]
fn singular_end_only_and_agreeing_assembled_terminal_keep_exact_bytes() {
    let accepted = call("call-assembled", TOOL_NAME, "{}");
    for end in [
        json!({"type":"tool-call-end","tool_call":accepted}),
        json!({"type":"tool-call-end","delta":{"tool_call":accepted}}),
    ] {
        preserves(
            frame(Some("tool-call-end"), end.clone()).into_bytes(),
            json!({}),
        );
        preserves(assembled(end), json!({}));
    }
}
