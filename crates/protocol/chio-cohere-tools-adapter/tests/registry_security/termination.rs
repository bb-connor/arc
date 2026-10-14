use super::*;

fn call_end(id: &str) -> String {
    frame(
        Some("tool-call-end"),
        json!({"type":"tool-call-end","tool_call":{"id":id,"type":"function",
            "function":{"name":TOOL_NAME,"arguments":"{}"}}}),
    )
}

fn message_start() -> String {
    frame(Some("message-start"), json!({"type":"message-start"}))
}

fn message_end() -> String {
    frame(
        Some("message-end"),
        json!({"type":"message-end","delta":{"finish_reason":"COMPLETE"}}),
    )
}

#[test]
fn empty_stream_is_not_complete() {
    assert_malformed("", "Cohere stream ended before message-end");
}

#[test]
fn stream_without_message_start_is_refused() {
    assert_malformed(
        &format!("{}{}", call_end("call-unopened"), message_end()),
        "Cohere stream must begin with message-start",
    );
    assert_malformed(
        &frame(Some("content-delta"), json!({"type":"content-delta"})),
        "Cohere stream must begin with message-start",
    );
}

#[test]
fn stream_truncated_after_a_complete_tool_call_is_refused() {
    assert_malformed(
        &format!("{}{}", message_start(), call_end("call-truncated")),
        "Cohere stream ended before message-end",
    );
}

#[test]
fn stream_truncated_inside_a_tool_call_is_refused() {
    assert_malformed(
        &format!(
            "{}{}{}",
            message_start(),
            start_frame(""),
            delta_frame("{}")
        ),
        "Cohere stream ended before the tool call ended",
    );
}

#[test]
fn message_end_inside_a_tool_call_is_refused() {
    assert_malformed(
        &format!("{}{}{}", message_start(), start_frame("{}"), message_end()),
        "Cohere message-end arrived inside a tool call",
    );
}

#[test]
fn second_message_start_is_refused() {
    assert_malformed(
        &format!(
            "{}{}{}{}",
            message_start(),
            message_start(),
            call_end("call-nested"),
            message_end()
        ),
        "Cohere message-start arrived inside an open message",
    );
}

#[test]
fn tool_call_after_message_end_is_refused() {
    assert_malformed(
        &format!(
            "{}{}{}",
            message_start(),
            message_end(),
            call_end("call-trailing")
        ),
        "Cohere SSE frame arrived after message-end",
    );
}

#[test]
fn any_frame_after_message_end_is_refused() {
    for trailing in [
        message_end(),
        message_start(),
        frame(Some("content-delta"), json!({"type":"content-delta"})),
        ": keepalive\n\n".to_string(),
    ] {
        assert_malformed(
            &format!(
                "{}{}{}{}",
                message_start(),
                call_end("call-complete"),
                message_end(),
                trailing
            ),
            "Cohere SSE frame arrived after message-end",
        );
    }
}

#[test]
fn terminated_stream_with_tool_call_is_evaluated() {
    let raw = format!(
        "{}{}{}",
        message_start(),
        call_end("call-complete"),
        message_end()
    );
    assert_eq!(gate(raw.as_bytes()).test_unwrap(), 1);
}
