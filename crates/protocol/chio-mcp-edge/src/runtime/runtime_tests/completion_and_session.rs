#[test]
fn resources_unsubscribe_clears_session_state() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );
    let mut edge = ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            resources_subscribe: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/subscribe",
        "params": { "uri": "repo://docs/architecture" }
    }));
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/unsubscribe",
            "params": { "uri": "repo://docs/architecture" }
        }))
        .unwrap();

    assert_eq!(response["result"], json!({}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    assert!(!edge
        .kernel
        .session_has_resource_subscription(&session_id, "repo://docs/architecture")
        .unwrap());
}

#[test]
fn resource_update_notifications_only_emit_for_subscribed_uris() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );
    let mut edge = ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            resources_subscribe: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/subscribe",
        "params": { "uri": "repo://docs/architecture" }
    }));

    edge.notify_resource_updated("repo://secret/ops");
    assert!(edge.take_pending_notifications().is_empty());

    edge.notify_resource_updated("repo://docs/architecture");
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/resources/updated"
    );
    assert_eq!(notifications[0]["params"]["uri"], "repo://docs/architecture");
}

#[test]
fn resources_list_changed_notification_emits_when_enabled() {
    let mut edge = make_edge(10);
    edge.config.resources_list_changed = true;

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    edge.notify_resources_list_changed();
    let notifications = edge.take_pending_notifications();

    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/resources/list_changed"
    );
    assert!(notifications[0].get("params").is_none());
}

#[test]
fn prompts_list_and_get_are_filtered_by_capabilities() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let list_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/list",
            "params": {}
        }))
        .unwrap();

    let prompts = list_response["result"]["prompts"].as_array().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0]["name"], "summarize_docs");

    let get_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "prompts/get",
            "params": { "name": "summarize_docs", "arguments": { "topic": "architecture" } }
        }))
        .unwrap();

    assert_eq!(
        get_response["result"]["messages"][0]["content"]["text"],
        "Summarize architecture"
    );
}

#[test]
fn completion_complete_returns_candidates_for_prompt_and_resource_refs() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let prompt_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/prompt", "name": "summarize_docs" },
                "argument": { "name": "topic", "value": "r" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(prompt_response["result"]["completion"]["total"], 2);
    assert_eq!(
        prompt_response["result"]["completion"]["values"],
        json!(["architecture", "release-notes"])
    );

    let resource_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "repo://docs/{slug}" },
                "argument": { "name": "slug", "value": "a" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(
        resource_response["result"]["completion"]["values"],
        json!(["architecture", "api"])
    );
}

#[test]
fn completion_complete_rejects_malformed_target_identifiers() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let malformed_prompt_name = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/prompt", "name": "" },
                "argument": { "name": "topic", "value": "r" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(
        malformed_prompt_name["error"]["message"],
        "prompt ref name must be a non-empty unpadded string without control characters"
    );

    let malformed_resource_uri = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": " repo://docs/{slug}" },
                "argument": { "name": "slug", "value": "a" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(
        malformed_resource_uri["error"]["message"],
        "resource ref uri must be a non-empty unpadded string without control characters"
    );

    let malformed_argument_name = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/prompt", "name": "summarize_docs" },
                "argument": { "name": "topic\n", "value": "r" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(
        malformed_argument_name["error"]["message"],
        "completion argument name must be a non-empty unpadded string without control characters"
    );
}

#[test]
fn logging_set_level_enables_warning_notifications_for_denied_calls() {
    let mut edge = make_edge_with_config(10, true);
    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(initialize["result"]["capabilities"]["logging"], json!({}));

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let set_level = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "logging/setLevel",
            "params": { "level": "warning" }
        }))
        .unwrap();
    assert_eq!(set_level["result"], json!({}));
    assert!(edge.take_pending_notifications().is_empty());

    let denied = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {}
            }
        }))
        .unwrap();
    assert_eq!(denied["result"]["isError"], true);

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/message");
    assert_eq!(notifications[0]["params"]["level"], "warning");
    assert_eq!(notifications[0]["params"]["logger"], "chio.mcp.tools");
    assert_eq!(notifications[0]["params"]["data"]["event"], "tool_denied");
}

#[test]
fn initialize_persists_configured_session_auth_context() {
    let mut edge = make_edge(10);
    let auth_context = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("http://localhost:3000".to_string()),
    );
    edge.set_session_auth_context(auth_context.clone());

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(
        initialize["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );

    let session_id = match &edge.state {
        EdgeState::WaitingForInitialized { session_id } => session_id.clone(),
        other => panic!("expected waiting-for-initialized state, got {other:?}"),
    };

    let session = edge.kernel.session(&session_id).expect("session exists");
    assert_eq!(session.auth_context(), auth_context);
}

#[test]
fn create_message_roundtrips_through_client_with_child_lineage() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "sampling": {
                    "context": {}
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
    let parent_context = OperationContext::new(
        session_id.clone(),
        RequestId::new("tool-parent"),
        edge.agent_id.clone(),
    );
    edge.kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: json!({
                "type": "text",
                "text": "Summarize the latest diff"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: Some("Be concise.".to_string()),
        include_context: Some("thisServer".to_string()),
        temperature: Some(0.1),
        max_tokens: 256,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    };

    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":",
            "{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"Summary ready.\"},\"model\":\"gpt-5.4\",\"stopReason\":\"endTurn\"}}\n"
        );
    let mut output = Vec::new();
    let result = edge
        .create_message(
            &parent_context,
            operation,
            &mut Cursor::new(input.as_bytes()),
            &mut output,
        )
        .unwrap();

    assert_eq!(result.model, "gpt-5.4");
    assert_eq!(result.content["text"], "Summary ready.");

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "sampling/createMessage");
    assert_eq!(messages[0]["params"]["includeContext"], "thisServer");
    assert_eq!(
        messages[0]["params"]["messages"][0]["content"]["text"],
        "Summarize the latest diff"
    );

    let session = edge.kernel.session(&session_id).unwrap();
    assert!(session
        .inflight()
        .get(&RequestId::new("tool-parent"))
        .is_some());
    assert!(session
        .inflight()
        .get(&RequestId::new("mcp-edge-req-1"))
        .is_none());
}

#[test]
fn create_message_denies_tool_use_when_not_negotiated() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "sampling": {}
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
    let parent_context = OperationContext::new(
        session_id.clone(),
        RequestId::new("tool-parent"),
        edge.agent_id.clone(),
    );
    edge.kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: json!({
                "type": "text",
                "text": "Search the docs first"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 128,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![SamplingTool {
            name: "search_docs".to_string(),
            description: Some("Search docs".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        }],
        tool_choice: Some(SamplingToolChoice {
            mode: "auto".to_string(),
        }),
    };

    let mut output = Vec::new();
    let error = edge
        .create_message(
            &parent_context,
            operation,
            &mut Cursor::new(b""),
            &mut output,
        )
        .unwrap_err();
    match error {
        AdapterError::NestedFlowDenied(message) => {
            assert!(message.contains("tool use"));
        }
        other => panic!("unexpected error: {other}"),
    }
    assert!(output.is_empty());
    assert!(edge
        .kernel
        .session(&session_id)
        .unwrap()
        .inflight()
        .get(&RequestId::new("mcp-edge-req-1"))
        .is_none());
}

#[test]
fn serve_stdio_requests_roots_after_initialized_and_updates_session() {
    let mut edge = make_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"roots\":{\"listChanged\":true}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project\",\"name\":\"Project\"}]}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(messages[1]["method"], "roots/list");

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let session = edge.kernel.session(&session_id).unwrap();
    assert!(session.peer_capabilities().supports_roots);
    assert!(session.peer_capabilities().roots_list_changed);
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project");
}

#[test]
fn restore_ready_session_requests_roots_and_updates_session() {
    let mut edge = make_edge(10);
    let session_id = SessionId::new("sess-restored-roots");
    edge.restore_ready_session(
        session_id.clone(),
        PeerCapabilities {
            supports_roots: true,
            roots_list_changed: false,
            ..PeerCapabilities::default()
        },
    )
    .unwrap();

    let (client_tx, client_rx) = mpsc::channel();
    client_tx
        .send(ClientInbound::Message(json!({
            "jsonrpc": "2.0",
            "id": "edge-client-1",
            "result": {
                "roots": [{
                    "uri": "file:///workspace/restored",
                    "name": "Restored"
                }]
            }
        })))
        .unwrap();
    drop(client_tx);

    let mut output = Vec::new();
    edge.process_pending_actions_with_channel(&client_rx, &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "roots/list");

    let session = edge.kernel.session(&session_id).unwrap();
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/restored");
    assert_eq!(session.roots()[0].name.as_deref(), Some("Restored"));
}

#[test]
fn serve_stdio_refreshes_roots_after_list_changed_notification() {
    let mut edge = make_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"roots\":{\"listChanged\":true}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project-a\",\"name\":\"Project A\"}]}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/roots/list_changed\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-2\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project-b\",\"name\":\"Project B\"}]}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[1]["method"], "roots/list");
    assert_eq!(messages[2]["method"], "roots/list");

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let session = edge.kernel.session(&session_id).unwrap();
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project-b");
    assert_eq!(session.roots()[0].name.as_deref(), Some("Project B"));
}

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

    let (client_tx, client_rx) = mpsc::channel();
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
    edge.refresh_roots_from_client_with_channel(&session_id, &client_rx, &mut output)
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
