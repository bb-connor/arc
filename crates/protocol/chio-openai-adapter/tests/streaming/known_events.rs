use super::final_callset::admitted_adapter;
use super::*;

fn rejects_unknown(event: &str) {
    let (adapter, _) = admitted_adapter();
    let raw = sse(&[(
        event,
        json!({"type":event,"delta":"untrusted","item":{"type":"function_call","call_id":"hidden","name":"get_weather","arguments":"{}"}}),
    )]);
    let mut evaluated = 0;
    let result = adapter.gate_sse_stream(raw.as_bytes(), |_| {
        evaluated += 1;
        Ok(allow_verdict())
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "unknown suffix passed: {result:?}"
    );
    assert_eq!(evaluated, 0);
}

#[test]
fn output_text_unknown_suffix_cannot_use_known_family_as_admission() {
    rejects_unknown("response.output_text.unpinned_tool_call");
}

#[test]
fn content_part_unknown_suffix_cannot_use_known_family_as_admission() {
    rejects_unknown("response.content_part.unpinned_tool_call");
}

#[test]
fn audio_unknown_suffix_cannot_use_known_family_as_admission() {
    rejects_unknown("response.audio.unpinned_tool_call");
}

#[test]
fn documented_content_text_audio_and_annotation_events_keep_exact_bytes() {
    // Exact current advertised family members, checked against the official
    // Responses streaming reference. No prefix admits an arbitrary suffix.
    let events = [
        (
            "response.content_part.added",
            json!({"type":"response.content_part.added","item_id":"m","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[],"logprobs":[]},"sequence_number":1}),
        ),
        (
            "response.output_text.delta",
            json!({"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"ok","logprobs":[],"sequence_number":2}),
        ),
        (
            "response.output_text.annotation.added",
            json!({"type":"response.output_text.annotation.added","item_id":"m","output_index":0,"content_index":0,"annotation_index":0,"annotation":null,"sequence_number":3}),
        ),
        (
            "response.output_text.done",
            json!({"type":"response.output_text.done","item_id":"m","output_index":0,"content_index":0,"text":"ok","logprobs":[],"sequence_number":4}),
        ),
        (
            "response.content_part.done",
            json!({"type":"response.content_part.done","item_id":"m","output_index":0,"content_index":0,"part":{"type":"output_text","text":"ok","annotations":[],"logprobs":[]},"sequence_number":5}),
        ),
        (
            "response.audio.delta",
            json!({"type":"response.audio.delta","delta":"b2s=","sequence_number":6}),
        ),
        (
            "response.audio.done",
            json!({"type":"response.audio.done","sequence_number":7}),
        ),
        (
            "response.audio.transcript.delta",
            json!({"type":"response.audio.transcript.delta","delta":"ok","sequence_number":8}),
        ),
        (
            "response.audio.transcript.done",
            json!({"type":"response.audio.transcript.done","sequence_number":9}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"id":"healthy","output":[]}}),
        ),
    ];
    let raw = sse(&events);
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
    assert_eq!(evaluated, 0);
}
