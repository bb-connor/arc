use super::final_callset::admitted_adapter;
use super::*;

fn item() -> serde_json::Value {
    json!({"type":"function_call","id":"item-a","call_id":"a",
        "name":"get_weather","arguments":"{\"city\":\"London\"}"})
}

fn stream(mut start: serde_json::Value, done: serde_json::Value) -> String {
    start["arguments"] = json!("");
    sse(&[
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":0,"item":start}),
        ),
        (
            "response.function_call_arguments.done",
            json!({"type":"response.function_call_arguments.done","output_index":0,
                "item_id":done["id"],"call_id":done["call_id"],
                "arguments":done["arguments"]}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":0,"item":done}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"output":[item()]}}),
        ),
    ])
}

fn rejects(raw: String) {
    let (adapter, _) = admitted_adapter();
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |invocation| {
        evaluated += 1;
        assert_eq!(invocation.tool_name, "get_weather");
        assert_eq!(invocation.provenance.request_id, "a");
        Ok(allow_verdict())
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "raw identity was normalized into an admitted call: {result:?}"
    );
    assert_eq!(evaluated, 0, "aliased raw identity reached evaluation");
}

#[test]
fn review_followup_surrounding_whitespace_tool_name_cannot_alias_admitted_name() {
    for name in [" get_weather", "get_weather ", "\tget_weather\n"] {
        let mut call = item();
        call["name"] = json!(name);
        rejects(stream(call.clone(), call));
    }
}

#[test]
fn review_followup_surrounding_whitespace_call_id_cannot_alias_final_identity() {
    for id in [" a", "a ", "\ta\n"] {
        let mut call = item();
        call["call_id"] = json!(id);
        rejects(stream(call.clone(), call));
    }
}

#[test]
fn review_followup_padded_item_id_cannot_match_a_distinct_literal_item_id() {
    for id in [" item-a", "item-a ", "\titem-a\n"] {
        let mut start = item();
        start["id"] = json!(id);
        rejects(stream(start, item()));
    }
}

#[test]
fn review_followup_literal_identities_preserve_exact_bytes_and_signed_registry_context() {
    let (adapter, flow) = admitted_adapter();
    let raw = stream(item(), item()) + ": literal context\n\ndata: [DONE]\n\n";
    let mut evaluated = 0;
    let gated = adapter
        .gate_sse_stream(raw.as_bytes(), |invocation| {
            evaluated += 1;
            assert_eq!(invocation.tool_name, "get_weather");
            assert_eq!(invocation.provenance.request_id, "a");
            assert_eq!(
                invocation.arguments,
                canonical_json_bytes(&json!({"city":"London"})).unwrap()
            );
            let security = invocation.bridge_security.as_ref().unwrap();
            assert!(security.has_registry_coordinates());
            assert_eq!(
                canonical_json_bytes(security.flow().unwrap()).unwrap(),
                canonical_json_bytes(&flow).unwrap()
            );
            Ok(allow_verdict())
        })
        .unwrap();
    assert_eq!(gated.bytes, raw.as_bytes());
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.verdicts, vec![allow_verdict()]);
    assert_eq!(evaluated, 1);
}
