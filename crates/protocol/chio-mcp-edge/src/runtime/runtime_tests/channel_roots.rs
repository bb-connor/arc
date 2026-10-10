use super::*;

#[test]
fn refresh_roots_with_channel_defers_unrelated_requests() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "roots": {
                    "listChanged": true
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };

    let (client_tx, mut client_rx) = mpsc::channel();
    client_tx
        .send(ClientInbound::Message(json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/tmp/example.txt"
                }
            }
        })))
        .unwrap();
    client_tx
        .send(ClientInbound::Message(json!({
            "jsonrpc": "2.0",
            "id": "edge-client-1",
            "result": {
                "roots": [{
                    "uri": "file:///workspace/project",
                    "name": "Project"
                }]
            }
        })))
        .unwrap();
    drop(client_tx);

    let mut output = Vec::new();
    edge.refresh_roots_from_client_with_channel(&session_id, &mut client_rx, &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "roots/list");

    assert_eq!(edge.deferred_client_messages.len(), 1);
    assert_eq!(edge.deferred_client_messages[0]["method"], "tools/call");

    let session = edge.kernel.session(&session_id).unwrap();
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project");
    assert_eq!(session.roots()[0].name.as_deref(), Some("Project"));
}

#[test]
fn roots_refresh_refuses_aggregate_deferred_ingress() {
    let mut edge = make_edge(10);
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"capabilities":{"roots":{"listChanged":true}}}}));
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let (sender, mut receiver) = mpsc::channel();
    for _ in 0..18 {
        sender
            .send(ClientInbound::Message(json!({"jsonrpc":"2.0",
            "method":"notifications/message","params":{"data":"x".repeat(512 * 1024)}})))
            .unwrap();
    }
    sender
        .send(ClientInbound::Message(
            json!({"jsonrpc":"2.0","id":"edge-client-1",
        "result":{"roots":[]}}),
        ))
        .unwrap();
    drop(sender);
    let result =
        edge.refresh_roots_from_client_with_channel(&session_id, &mut receiver, &mut Vec::new());
    assert!(result.is_err(), "unbounded deferred input was admitted");
}

#[test]
fn borrowed_client_reader_refuses_before_emitting_request() {
    let mut edge = make_edge(10);
    let mut reader = Cursor::new(b"{\"id\":\"edge-client-1\",\"result\":{\"roots\":[]}}\n");
    let mut output = Vec::new();
    let result = edge.send_client_request(&mut reader, &mut output, "roots/list", json!({}));
    assert!(
        result.is_err(),
        "borrowed readers cannot enforce a reply deadline"
    );
    assert!(
        output.is_empty(),
        "unsupported wait emitted a client request"
    );
    assert_eq!(reader.position(), 0);

    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"capabilities":{"sampling":{"context":{}}}}}));
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let parent = OperationContext::new(
        session_id.clone(),
        RequestId::new("borrowed-parent"),
        edge.agent_id.clone(),
    );
    edge.kernel
        .begin_session_request(&parent, OperationKind::ToolCall, true)
        .unwrap();
    assert!(edge
        .create_message(&parent, sampling_operation(), &mut reader, &mut output)
        .is_err());
    assert!(output.is_empty());
    assert_eq!(reader.position(), 0);
    assert_eq!(edge.child_request_counter, 0);
    assert_eq!(edge.client_request_counter, 0);
    assert_eq!(
        edge.kernel.session(&session_id).unwrap().inflight().len(),
        1
    );
}

#[test]
fn roots_reply_result_retains_original_reservation_until_handling_finishes() {
    let mut edge = make_edge(10);
    let (sender, mut receiver) = mcp_inbox();
    edge.inbox_admission = receiver.admission.clone();
    let wire = br#"{"jsonrpc":"2.0","id":"edge-client-1","result":{"roots":[]}}"#;
    sender.send(sender.decode(wire, 4096).unwrap()).unwrap();
    let admitted = sender.usage().unwrap();
    let reply = edge
        .send_client_request_with_channel(
            &mut receiver.receiver,
            &mut Vec::new(),
            "roots/list",
            json!({}),
        )
        .unwrap();
    assert_eq!(reply["roots"], json!([]));
    assert_eq!(
        sender.usage().unwrap(),
        admitted,
        "reply handling released the original admission before its result"
    );
    drop(reply);
    assert_eq!(
        sender.usage().unwrap(),
        crate::ingress::IngressUsage::default()
    );
}

#[test]
fn sampling_inbox_replacement_refuses_foreign_deferred_ownership_before_effects() {
    let mut edge = make_edge(10);
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"capabilities":{"sampling":{"context":{}}}}}));
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let parent = OperationContext::new(
        session_id.clone(),
        RequestId::new("owner-parent"),
        edge.agent_id.clone(),
    );
    edge.kernel
        .begin_session_request(&parent, OperationKind::ToolCall, true)
        .unwrap();
    let (old_sender, mut old_receiver) = mcp_inbox();
    edge.inbox_admission = old_receiver.admission.clone();
    edge.deferred_client_messages.push_back(
        old_sender
            .decode(
                br#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#,
                4096,
            )
            .unwrap(),
    );
    let original = old_sender.usage().unwrap();
    let (new_sender, mut inbox) = mcp_inbox();
    new_sender.send(new_sender.decode(br#"{"jsonrpc":"2.0","id":"edge-client-1","result":{"role":"assistant","content":{"type":"text","text":"Summary"},"model":"model"}}"#, 4096).unwrap()).unwrap();
    let mut output = Vec::new();
    let result = edge.create_message_with_client_inbox(
        &parent,
        sampling_operation(),
        &mut inbox,
        &mut output,
    );
    assert!(
        matches!(result, Err(AdapterError::IngressCapacity)),
        "inbox replacement retained independent deferred budgets: {result:?}"
    );
    assert!(output.is_empty());
    assert_eq!(edge.child_request_counter, 0);
    assert_eq!(edge.client_request_counter, 0);
    assert_eq!(
        edge.kernel.session(&session_id).unwrap().inflight().len(),
        1
    );
    assert_eq!(edge.deferred_client_messages.len(), 1);
    assert_eq!(old_sender.usage().unwrap(), original);
    old_sender.send(old_sender.decode(br#"{"jsonrpc":"2.0","id":"edge-client-1","result":{"role":"assistant","content":{"type":"text","text":"Summary"},"model":"model"}}"#, 4096).unwrap()).unwrap();
    let result = edge
        .create_message_with_client_inbox(
            &parent,
            sampling_operation(),
            &mut old_receiver,
            &mut output,
        )
        .unwrap();
    assert_eq!(result.model, "model");
    assert!(!output.is_empty());
    assert_eq!(edge.deferred_client_messages.len(), 1);
    assert_eq!(old_sender.usage().unwrap(), original);
}

fn sampling_operation() -> CreateMessageOperation {
    CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".into(),
            content: json!({"type":"text","text":"Summarize"}),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 1,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    }
}
