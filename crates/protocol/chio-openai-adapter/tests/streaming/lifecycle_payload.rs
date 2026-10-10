use super::final_callset::admitted_adapter;
use super::*;

fn lifecycle_stream(event: &str, output: Option<serde_json::Value>) -> String {
    let mut response = json!({"id":"response-context","object":"response",
        "model":"synthetic-fixture","metadata":{"context":"preserved"}});
    if let Some(output) = output {
        response["output"] = output;
    }
    sse(&[
        (event, json!({"type":event,"response":response})),
        (
            "response.completed",
            json!({"type":"response.completed","response":{
                "id":"response-context","output":[]}}),
        ),
    ]) + ": preserved comment\n\ndata: [DONE]\n\n"
}

fn rejects_hidden_call(event: &str) {
    let (adapter, _) = admitted_adapter();
    let raw = lifecycle_stream(
        event,
        Some(json!([{"type":"function_call","id":"hidden-item",
            "call_id":"hidden","name":"get_weather","arguments":"{}"}])),
    );
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |_| {
        evaluated += 1;
        Ok(allow_verdict())
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "lifecycle executable output was forwarded: {result:?}"
    );
    assert_eq!(
        evaluated, 0,
        "unsupported lifecycle call reached evaluation"
    );
}

#[test]
fn review_followup_created_lifecycle_output_cannot_forward_unevaluated_function_call() {
    rejects_hidden_call("response.created");
}

#[test]
fn review_followup_in_progress_lifecycle_output_cannot_forward_unevaluated_function_call() {
    rejects_hidden_call("response.in_progress");
}

#[test]
fn review_followup_queued_lifecycle_output_cannot_forward_unevaluated_function_call() {
    rejects_hidden_call("response.queued");
}

#[test]
fn review_followup_absent_empty_and_provider_rendered_lifecycle_output_preserve_context_and_exact_bytes(
) {
    for event in [
        "response.created",
        "response.in_progress",
        "response.queued",
    ] {
        for output in [
            None,
            Some(json!([])),
            Some(json!([
                {"type":"message","id":"message-context","role":"assistant",
                    "content":[{"type":"output_text","text":"ok","annotations":[]}]},
                {"type":"reasoning","id":"reasoning-context","summary":[]}
            ])),
        ] {
            let raw = lifecycle_stream(event, output);
            let (adapter, _) = admitted_adapter();
            let mut evaluated = 0;
            let gated = adapter
                .gate_sse_stream(raw.as_bytes(), |_| {
                    evaluated += 1;
                    Ok(allow_verdict())
                })
                .unwrap();
            assert_eq!(gated.bytes, raw.as_bytes());
            assert!(gated.invocations.is_empty());
            assert!(gated.verdicts.is_empty());
            assert!(gated.buffered_blocks.is_empty());
            assert_eq!(evaluated, 0);
        }
    }
}
