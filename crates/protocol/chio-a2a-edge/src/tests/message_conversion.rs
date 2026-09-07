// ---- Message extraction tests ----

#[test]
fn extract_text_from_parts() {
    let msg = A2aMessage {
        role: "user".to_string(),
        parts: vec![A2aPart::Text {
            text: "hello world".to_string(),
        }],
        metadata: None,
    };
    let args = extract_arguments_from_message(&msg).test_unwrap();
    assert_eq!(args["message"], "hello world");
}

#[test]
fn extract_data_from_parts() {
    let msg = A2aMessage {
        role: "user".to_string(),
        parts: vec![A2aPart::Data {
            data: json!({"key": "value"}),
        }],
        metadata: None,
    };
    let args = extract_arguments_from_message(&msg).test_unwrap();
    assert_eq!(args["key"], "value");
}

#[test]
fn extract_rejects_scalar_data_part_arguments() {
    let msg = A2aMessage {
        role: "user".to_string(),
        parts: vec![A2aPart::Data {
            data: json!("not-an-argument-object"),
        }],
        metadata: None,
    };

    let error = extract_arguments_from_message(&msg)
        .test_expect_err("scalar data parts must fail before dispatch");
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert!(message.contains("data part must be a JSON object"));
}

#[test]
fn extract_rejects_array_data_part_arguments() {
    let msg = A2aMessage {
        role: "user".to_string(),
        parts: vec![A2aPart::Data {
            data: json!(["not", "an", "argument", "object"]),
        }],
        metadata: None,
    };

    let error = extract_arguments_from_message(&msg)
        .test_expect_err("array data parts must fail before dispatch");
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert!(message.contains("data part must be a JSON object"));
}

#[test]
fn extract_prefers_data_over_text() {
    let msg = A2aMessage {
        role: "user".to_string(),
        parts: vec![
            A2aPart::Text {
                text: "hello".to_string(),
            },
            A2aPart::Data {
                data: json!({"priority": "high"}),
            },
        ],
        metadata: None,
    };
    let args = extract_arguments_from_message(&msg).test_unwrap();
    assert_eq!(args["priority"], "high");
}

#[test]
fn compatibility_send_rejects_multiple_data_parts() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig::default(),
        vec![{
            let mut m = test_manifest();
            m.tools.truncate(1);
            m
        }],
    )
    .test_unwrap();
    let server = test_server();
    let request = SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![
                A2aPart::Data {
                    data: json!({"first": true}),
                },
                A2aPart::Data {
                    data: json!({"second": true}),
                },
            ],
            metadata: None,
        },
        metadata: None,
    };

    let error = edge
        .compatibility()
        .handle_send_message_compatibility("echo", &request, &server)
        .test_expect_err("multiple A2A data parts must fail");
    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert!(message.contains("at most one data part"));
}

// ---- Result conversion tests ----

#[test]
fn result_text_to_parts() {
    let parts = result_to_parts(&json!("hello"));
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        A2aPart::Text { text } => assert_eq!(text, "hello"),
        _ => panic!("expected text part"),
    }
}

#[test]
fn result_object_to_data_parts() {
    let parts = result_to_parts(&json!({"key": "value"}));
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        A2aPart::Data { data } => assert_eq!(data["key"], "value"),
        _ => panic!("expected data part"),
    }
}

#[test]
fn result_content_array_to_text_parts() {
    let parts = result_to_parts(&json!({
        "content": [
            {"type": "text", "text": "part1"},
            {"type": "text", "text": "part2"},
        ]
    }));
    assert_eq!(parts.len(), 2);
}
