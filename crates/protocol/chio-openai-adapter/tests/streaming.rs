#![cfg(feature = "provider-adapter")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_openai::adapter::{OpenAiAdapter, OpenAiAdapterConfig};
use chio_tool_call_fabric::{
    DenyReason, ProviderError, ProviderId, ReceiptId, VerdictResult,
    DEFAULT_MAX_BUFFERED_RAW_FRAMES,
};
use serde_json::json;

#[path = "streaming/final_callset.rs"]
mod final_callset;
#[path = "streaming/known_events.rs"]
mod known_events;

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_stream_1".to_string()),
    }
}

fn policy_deny_verdict() -> VerdictResult {
    VerdictResult::Deny {
        reason: DenyReason::PolicyDeny {
            rule_id: "deny_calendar".to_string(),
        },
        receipt_id: ReceiptId("rcpt_deny_stream_1".to_string()),
    }
}

fn tool_call_stream() -> &'static str {
    concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_stream_1\"}}\n\n",
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\"}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"\\\"Chio sync\\\",\\\"duration_minutes\\\":30}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_calendar_1\",\"arguments\":\"{\\\"title\\\":\\\"Chio sync\\\",\\\"duration_minutes\\\":30}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"Chio sync\\\",\\\"duration_minutes\\\":30}\"}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_1\"}}\n\n",
    )
}

fn config_with_api_version(api_version: &str) -> OpenAiAdapterConfig {
    let mut config = OpenAiAdapterConfig::new("org_chio_demo");
    config.api_version = api_version.to_string();
    config
}

fn assert_api_version_drift(error: ProviderError) {
    match error {
        ProviderError::Malformed(message) => {
            assert!(
                message.contains("OpenAI adapter supports only API version responses.2026-04-25")
            );
            assert!(message.contains("configured responses.2025-01-01"));
        }
        other => panic!("expected Malformed API version drift, got {other:?}"),
    }
}

#[test]
fn gate_sse_stream_rejects_api_version_drift_before_evaluator() {
    let adapter = OpenAiAdapter::new(config_with_api_version("responses.2025-01-01"));
    let mut evaluated = false;

    let err = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |_| {
            evaluated = true;
            Ok(allow_verdict())
        })
        .expect_err("drifted OpenAI Responses API version must fail before stream evaluation");

    assert_api_version_drift(err);
    assert!(!evaluated);
}

#[test]
fn buffers_function_call_argument_deltas_until_done_verdict_allows() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut evaluated = Vec::new();
    let gated = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |invocation| {
            evaluated.push(invocation.provenance.request_id.clone());
            Ok(allow_verdict())
        })
        .unwrap();

    assert_eq!(evaluated, vec!["call_calendar_1"]);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].provider, ProviderId::OpenAi);
    assert_eq!(gated.invocations[0].tool_name, "create_calendar_event");
    assert_eq!(
        gated.invocations[0].arguments,
        canonical_json_bytes(&json!({
            "duration_minutes": 30,
            "title": "Chio sync"
        }))
        .unwrap()
    );
    assert_eq!(gated.verdicts, vec![allow_verdict()]);
    assert_eq!(gated.buffered_blocks.len(), 1);
    assert_eq!(gated.buffered_blocks[0].block_id, "call_calendar_1");
    assert_eq!(
        String::from_utf8(gated.buffered_blocks[0].bytes.clone()).unwrap(),
        "{\"title\":\"Chio sync\",\"duration_minutes\":30}"
    );

    let forwarded = String::from_utf8(gated.bytes).unwrap();
    assert!(forwarded.contains("response.created"));
    assert!(forwarded.contains("response.output_item.added"));
    assert!(forwarded.contains("response.function_call_arguments.delta"));
    assert!(forwarded.contains("response.function_call_arguments.done"));
    assert!(forwarded.contains("response.output_item.done"));
    assert!(forwarded.contains("response.completed"));
}

#[test]
fn done_sentinel_after_completed_is_idempotent() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = format!("{}data: [DONE]\n\n", tool_call_stream());

    let gated = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .unwrap();

    let forwarded = String::from_utf8(gated.bytes).unwrap();
    assert!(forwarded.contains("response.completed"));
    assert!(forwarded.ends_with("data: [DONE]\n\n"));
}

#[test]
fn deny_verdict_fails_closed_before_tool_frames_are_released() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |_| {
            calls += 1;
            Ok(policy_deny_verdict())
        })
        .expect_err("deny verdict should fail closed");

    assert_eq!(calls, 1);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("denied at output_item.done"));
    assert!(err.to_string().contains("deny_calendar"));
}

#[test]
fn mismatched_done_arguments_fail_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"arguments\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"different\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("mismatched streamed arguments should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("did not match"));
}

#[test]
fn missing_function_arguments_done_fails_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"queued\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("missing argument done should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err
        .to_string()
        .contains("without response.function_call_arguments.done"));
}

#[test]
fn mismatched_function_arguments_done_fails_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_calendar_1\",\"arguments\":\"{\\\"title\\\":\\\"forbidden\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"queued\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("argument done mismatch should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("did not match final arguments"));
}

#[test]
fn function_arguments_done_must_match_output_item_done_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_calendar_1\",\"arguments\":\"{\\\"title\\\":\\\"forbidden\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"safe\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("argument done and item done mismatch should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("arguments for tool call"));
}

#[test]
fn non_empty_start_arguments_with_delta_fail_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"secret\\\":\\\"forbidden\\\"}\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"safe\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"arguments\":\"{\\\"title\\\":\\\"safe\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"safe\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("non-empty start args plus deltas should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::BadToolArgs(_)));
    assert!(err.to_string().contains("mixed non-empty"));
}

#[test]
fn id_only_function_call_fails_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_fc_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"item_fc_1\",\"delta\":\"{}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"item_fc_1\",\"arguments\":\"{}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_fc_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("id-only function call must fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing non-empty call_id"));
}

#[test]
fn verdict_timeout_terminates_before_tool_frames_are_released() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let err = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |_| {
            Err(ProviderError::VerdictBudgetExceeded {
                observed_ms: 300,
                budget_ms: 250,
            })
        })
        .expect_err("timeout should fail closed");

    assert!(matches!(err, ProviderError::VerdictBudgetExceeded { .. }));
    assert!(err.to_string().contains("verdict latency budget exceeded"));
}

#[test]
fn malformed_delta_without_active_tool_call_fails_closed() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_orphan\",\"delta\":\"{}\"}\n\n",
    );

    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .expect_err("orphaned delta should fail closed");

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("without an active tool call"));
}

#[test]
fn malformed_done_tool_call_arguments_fail_closed() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_bad_args\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_bad_args\",\"name\":\"create_calendar_event\",\"arguments\":\"{not json\"}}\n\n",
    );

    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .expect_err("invalid done arguments should fail closed");

    assert!(matches!(
        err,
        ProviderError::UntrustedInput(chio_core::canonical::UntrustedJsonError::SignedInput(_))
    ));
    assert_eq!(
        err.to_string(),
        "urn:chio:error:attest:signed-json-invalid-input"
    );
}

#[test]
fn zero_length_argument_deltas_count_toward_buffered_frame_limit() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut raw = String::from(concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_many_empty\",\"call_id\":\"call_many_empty\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
    ));
    for _ in 0..4097 {
        raw.push_str(concat!(
            "event: response.function_call_arguments.delta\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_many_empty\",\"delta\":\"\"}\n\n",
        ));
    }
    raw.push_str(concat!(
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_many_empty\",\"arguments\":\"{}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_many_empty\",\"call_id\":\"call_many_empty\",\"name\":\"create_calendar_event\",\"arguments\":\"{}\"}}\n\n",
    ));

    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .expect_err("too many buffered raw frames should fail closed");

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("raw frame count"));
}

#[test]
fn output_item_done_is_forwarded_when_pre_verdict_frames_reach_limit() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut raw = String::from(concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_limit\",\"call_id\":\"call_limit\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
    ));
    for _ in 0..(DEFAULT_MAX_BUFFERED_RAW_FRAMES - 2) {
        raw.push_str(concat!(
            "event: response.function_call_arguments.delta\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_limit\",\"delta\":\"\"}\n\n",
        ));
    }
    raw.push_str(concat!(
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_limit\",\"arguments\":\"{}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_limit\",\"call_id\":\"call_limit\",\"name\":\"create_calendar_event\",\"arguments\":\"{}\"}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_limit\"}}\n\n",
    ));

    let mut calls = 0;
    let gated = adapter
        .gate_sse_stream(raw.as_bytes(), |invocation| {
            calls += 1;
            assert_eq!(invocation.provenance.request_id, "call_limit");
            Ok(allow_verdict())
        })
        .unwrap();

    assert_eq!(calls, 1);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.verdicts, vec![allow_verdict()]);
    let forwarded = String::from_utf8(gated.bytes).unwrap();
    assert!(forwarded.contains("response.output_item.done"));
    assert!(forwarded.contains("response.completed"));
}

#[test]
fn non_append_start_frame_bytes_count_toward_buffered_raw_byte_limit() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let padding = "x".repeat(2 * 1024 * 1024 + 2048);
    let raw = format!(
        concat!(
            "event: response.output_item.added\n",
            "data: {{\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{{\"type\":\"function_call\",\"id\":\"fc_huge_start\",\"call_id\":\"call_huge_start\",\"name\":\"create_calendar_event\",\"arguments\":\"\",\"padding\":\"{}\"}}}}\n\n",
            "event: response.output_item.done\n",
            "data: {{\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{{\"type\":\"function_call\",\"id\":\"fc_huge_start\",\"call_id\":\"call_huge_start\",\"name\":\"create_calendar_event\",\"arguments\":\"{{}}\"}}}}\n\n",
        ),
        padding
    );

    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .expect_err("oversized non-append raw frame should fail closed");

    assert!(matches!(
        err,
        ProviderError::UntrustedInput(chio_core::canonical::UntrustedJsonError::TooLarge { .. })
    ));
}

fn sse(events: &[(&str, serde_json::Value)]) -> String {
    events
        .iter()
        .map(|(event, data)| format!("event: {event}\ndata: {data}\n\n"))
        .collect()
}

fn assert_rejected_without_evaluation(stream: &str) {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut evaluated = 0_usize;
    let result = adapter.gate_sse_stream(stream.as_bytes(), |_| {
        evaluated += 1;
        Ok(allow_verdict())
    });
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "stream must fail closed, got {result:?}"
    );
    assert_eq!(evaluated, 0);
}

#[test]
fn client_executed_local_shell_call_item_fails_closed() {
    let item = json!({"type":"local_shell_call","id":"lsh_1","call_id":"call_shell_1",
        "action":{"type":"exec","command":["rm","-rf","/work"]},"status":"completed"});
    assert_rejected_without_evaluation(&sse(&[
        (
            "response.created",
            json!({"type":"response.created","response":{"id":"resp_1"}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":0,"item":item}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":0,"item":item}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"id":"resp_1","output":[item]}}),
        ),
    ]));
}

#[test]
fn custom_tool_call_item_fails_closed() {
    let item = json!({"type":"custom_tool_call","id":"ctc_1","call_id":"call_patch_1",
        "name":"apply_patch","input":"*** Begin Patch"});
    assert_rejected_without_evaluation(&sse(&[
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":0,"item":item}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":0,"item":item}),
        ),
    ]));
}

#[test]
fn unknown_event_name_fails_closed() {
    assert_rejected_without_evaluation(&sse(&[
        (
            "response.created",
            json!({"type":"response.created","response":{"id":"resp_1"}}),
        ),
        (
            "response.future_client_action.done",
            json!({"type":"response.future_client_action.done"}),
        ),
    ]));
}

#[test]
fn completed_output_with_unevaluated_arguments_fails_closed() {
    let altered = json!({"type":"function_call","id":"fc_calendar_1","call_id":"call_calendar_1",
        "name":"create_calendar_event","arguments":"{\"title\":\"../../etc\",\"duration_minutes\":30}"});
    let stream = tool_call_stream().replace(
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_1\"}}",
        &format!("data: {}", json!({"type":"response.completed","response":{"id":"resp_stream_1","output":[altered]}})),
    );
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = adapter.gate_sse_stream(stream.as_bytes(), |_| Ok(allow_verdict()));
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "got {result:?}"
    );
}

#[test]
fn completed_output_with_an_extra_function_call_fails_closed() {
    let evaluated = json!({"type":"function_call","id":"fc_calendar_1","call_id":"call_calendar_1",
        "name":"create_calendar_event","arguments":"{\"title\":\"Chio sync\",\"duration_minutes\":30}"});
    let extra = json!({"type":"function_call","id":"fc_extra","call_id":"call_extra",
        "name":"delete_calendar","arguments":"{}"});
    let stream = tool_call_stream().replace(
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_1\"}}",
        &format!("data: {}", json!({"type":"response.completed","response":{"id":"resp_stream_1","output":[evaluated, extra]}})),
    );
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = adapter.gate_sse_stream(stream.as_bytes(), |_| Ok(allow_verdict()));
    assert!(
        matches!(result, Err(ProviderError::Malformed(_))),
        "got {result:?}"
    );
}

#[test]
fn completed_output_matching_the_evaluated_call_is_forwarded() {
    let evaluated = json!({"type":"function_call","id":"fc_calendar_1","call_id":"call_calendar_1",
        "name":"create_calendar_event","arguments":"{\"title\":\"Chio sync\",\"duration_minutes\":30}"});
    let message = json!({"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"done"}]});
    let stream = tool_call_stream().replace(
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_1\"}}",
        &format!("data: {}", json!({"type":"response.completed","response":{"id":"resp_stream_1","output":[evaluated, message]}})),
    );
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let gated = adapter
        .gate_sse_stream(stream.as_bytes(), |_| Ok(allow_verdict()))
        .unwrap();
    assert_eq!(gated.invocations.len(), 1);
}

#[test]
fn provider_executed_message_and_reasoning_items_are_forwarded() {
    let message = json!({"type":"message","id":"msg_1","role":"assistant","content":[]});
    let reasoning = json!({"type":"reasoning","id":"rs_1","summary":[]});
    let stream = sse(&[
        (
            "response.created",
            json!({"type":"response.created","response":{"id":"resp_1"}}),
        ),
        (
            "response.in_progress",
            json!({"type":"response.in_progress","response":{"id":"resp_1"}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":0,"item":reasoning}),
        ),
        (
            "response.reasoning_summary_text.delta",
            json!({"type":"response.reasoning_summary_text.delta","delta":"thinking"}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":0,"item":reasoning}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":1,"item":message}),
        ),
        (
            "response.content_part.added",
            json!({"type":"response.content_part.added","part":{"type":"output_text","text":""}}),
        ),
        (
            "response.output_text.delta",
            json!({"type":"response.output_text.delta","delta":"hello"}),
        ),
        (
            "response.output_text.done",
            json!({"type":"response.output_text.done","text":"hello"}),
        ),
        (
            "response.content_part.done",
            json!({"type":"response.content_part.done","part":{"type":"output_text","text":"hello"}}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":1,"item":message}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"id":"resp_1","output":[reasoning, message]}}),
        ),
    ]);
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let gated = adapter
        .gate_sse_stream(stream.as_bytes(), |_| Ok(allow_verdict()))
        .unwrap();
    assert!(gated.invocations.is_empty());
    assert!(String::from_utf8(gated.bytes)
        .unwrap()
        .contains("response.output_text.delta"));
}

#[path = "streaming/lifecycle_payload.rs"]
mod lifecycle_payload;

#[path = "streaming/raw_identity.rs"]
mod raw_identity;
