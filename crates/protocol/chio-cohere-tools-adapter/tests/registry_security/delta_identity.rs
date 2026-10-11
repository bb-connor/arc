use super::*;
use chio_tool_call_fabric::ProviderError;
use serde_json::Value;

pub(super) fn streamed(start_arguments: Value, extra: Value) -> Vec<u8> {
    let start = json!({"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{
        "id":"stream-call","type":"function","function":{"name":TOOL_NAME,"arguments":start_arguments}
    }}}});
    let mut call = json!({"function":{"arguments":"{\"city\":\"London\"}"}});
    for (key, value) in extra.as_object().test_unwrap() {
        if key == "name" {
            call["function"]["name"] = value.clone();
        } else {
            call[key] = value.clone();
        }
    }
    let delta = json!({"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":call}}});
    let end = json!({"type":"tool-call-end","index":0});
    format!("event: tool-call-start\ndata: {start}\n\nevent: tool-call-delta\ndata: {delta}\n\nevent: tool-call-end\ndata: {end}\n\n").into_bytes()
}

fn rejects(raw: Vec<u8>) {
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
        "identity/type mismatch was forwarded: {result:?}"
    );
    assert_eq!(
        evaluated.get(),
        0,
        "malformed identity reached the evaluator"
    );
}

#[test]
fn provided_delta_id_cannot_change_or_lose_string_type() {
    for id in [json!("different-call"), json!(false), json!(17)] {
        rejects(streamed(json!(""), json!({"id":id})));
    }
}

#[test]
fn provided_delta_name_cannot_change_or_lose_string_type() {
    for name in [json!("different_tool"), json!(false), json!({})] {
        rejects(streamed(json!(""), json!({"name":name})));
    }
}

#[test]
fn provided_delta_type_cannot_change_or_lose_string_type() {
    for kind in [json!("custom"), json!([]), json!(true)] {
        rejects(streamed(json!(""), json!({"type":kind})));
    }
}

#[test]
fn nontext_start_arguments_cannot_be_erased_by_later_delta() {
    for arguments in [
        json!({"secret":"start-only"}),
        json!([]),
        json!(1),
        json!(null),
    ] {
        rejects(streamed(arguments, json!({})));
    }
}

#[test]
fn optional_matching_delta_identity_preserves_bytes_and_signed_registry_flow() {
    for extra in [
        json!({}),
        json!({"id":"stream-call","name":TOOL_NAME,"type":"function"}),
    ] {
        let raw = streamed(json!(""), extra);
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
                    canonical_json_bytes(&json!({"city":"London"})).test_unwrap()
                );
                Ok(allow())
            })
            .test_unwrap();
        assert_eq!(gated.bytes, raw);
        assert_eq!(gated.invocations.len(), 1);
        assert_eq!(gated.verdicts, vec![allow()]);
        assert_eq!(evaluated.get(), 1);
    }
}
