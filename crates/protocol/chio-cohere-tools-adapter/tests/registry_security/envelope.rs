use super::*;
use chio_tool_call_fabric::ProviderError;

fn assembled_call() -> String {
    format!(
        "{}{}{}",
        start_frame(""),
        delta_frame("{\"city\":\"Paris\"}"),
        frame(
            Some("tool-call-end"),
            json!({"type":"tool-call-end","index":0})
        ),
    )
}

fn message_start() -> String {
    frame(
        Some("message-start"),
        json!({"type":"message-start","id":"msg-1"}),
    )
}

fn message_end() -> String {
    frame(
        Some("message-end"),
        json!({"type":"message-end","delta":{"finish_reason":"COMPLETE"}}),
    )
}

fn rejects_before_evaluation(raw: &str, expected: &str) {
    let (config, registry, _) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    let evaluated = Cell::new(0);
    let result = adapter.gate_sse_stream(raw.as_bytes(), |_| {
        evaluated.set(evaluated.get() + 1);
        Ok(allow())
    });
    match result {
        Err(ProviderError::Malformed(message)) => assert_eq!(message, expected),
        other => panic!("incomplete Cohere message was not refused: {other:?}"),
    }
    assert_eq!(evaluated.get(), 0, "incomplete message reached evaluation");
}

#[test]
fn complete_message_envelope_is_evaluated() {
    assert_eq!(gate(message(&assembled_call()).as_bytes()).test_unwrap(), 1);
}

#[test]
fn tool_call_without_message_envelope_fails_closed() {
    rejects_before_evaluation(
        &assembled_call(),
        "Cohere tool-call-start arrived before message-start",
    );
    rejects_before_evaluation(
        &format!("{}{}", assembled_call(), message_end()),
        "Cohere tool-call-start arrived before message-start",
    );
    rejects_before_evaluation(
        &message_end(),
        "Cohere message-end arrived before message-start",
    );
}

#[test]
fn tool_call_without_message_end_fails_closed() {
    rejects_before_evaluation(
        &format!("{}{}", message_start(), assembled_call()),
        "Cohere stream ended before message-end",
    );
}

#[test]
fn events_after_message_end_fail_closed() {
    rejects_before_evaluation(
        &format!("{}{}", message(""), assembled_call()),
        "Cohere tool-call-start arrived after message-end",
    );
    rejects_before_evaluation(
        &format!(
            "{}{}",
            message(&assembled_call()),
            message(&assembled_call())
        ),
        "Cohere message-start arrived after message-end",
    );
}

#[test]
fn repeated_message_start_fails_closed() {
    rejects_before_evaluation(
        &format!("{}{}", message_start(), message(&assembled_call())),
        "Cohere message-start repeated inside a message",
    );
}
