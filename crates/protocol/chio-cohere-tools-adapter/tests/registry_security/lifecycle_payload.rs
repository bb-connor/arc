use super::*;

fn lifecycle_stream(event: &str, carries_call: bool) -> Vec<u8> {
    let data = if carries_call {
        json!({
            "type": event,
            "delta": {"message": {"tool_calls": {
                "id": "lifecycle-call",
                "type": "function",
                "function": {"name": TOOL_NAME, "arguments": "{}"}
            }}}
        })
    } else {
        json!({"type": event})
    };
    let mut bytes = format!("event: {event}\ndata: {data}\n\n").into_bytes();
    if event == "message-start" {
        bytes.extend_from_slice(b"event: message-end\ndata: {\"type\":\"message-end\"}\n\n");
    }
    bytes
}

fn rejects_lifecycle_call(event: &str) {
    let (config, registry, _) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    let evaluated = Cell::new(0);
    let result = adapter.gate_sse_stream(&lifecycle_stream(event, true), |_| {
        evaluated.set(evaluated.get() + 1);
        Ok(allow())
    });

    assert!(
        matches!(
            result,
            Err(chio_tool_call_fabric::ProviderError::Malformed(_))
        ),
        "a lifecycle frame carrying an executable call must fail before forwarding"
    );
    assert_eq!(evaluated.get(), 0);
}

#[test]
fn message_start_cannot_forward_unevaluated_tool_call() {
    rejects_lifecycle_call("message-start");
}

#[test]
fn message_end_cannot_forward_unevaluated_tool_call() {
    rejects_lifecycle_call("message-end");
}

#[test]
fn ordinary_lifecycle_preserves_bytes_without_fabricating_invocations() {
    let (config, registry, _) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    let stream = lifecycle_stream("message-start", false);
    let evaluated = Cell::new(0);
    let gated = adapter
        .gate_sse_stream(&stream, |_| {
            evaluated.set(evaluated.get() + 1);
            Ok(allow())
        })
        .test_unwrap();

    assert_eq!(gated.bytes, stream);
    assert!(gated.invocations.is_empty());
    assert!(gated.verdicts.is_empty());
    assert_eq!(evaluated.get(), 0);
}
