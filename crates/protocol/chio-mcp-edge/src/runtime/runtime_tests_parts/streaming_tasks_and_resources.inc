#[test]
fn tools_call_returns_structured_content_for_object_results() {
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

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "echo_json", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["temperature"], 22.5);
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("temperature"));
}

#[test]
fn tools_call_denied_by_capabilities_returns_tool_error() {
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

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "write_file", "arguments": { "path": "/tmp/x", "content": "hi" } }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not authorized"));
}

#[test]
fn tools_call_streams_chunks_via_experimental_notifications_when_negotiated() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioToolStreaming": {
                        "toolCallChunkNotifications": true
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stream_file", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["mode"],
        "notification_stream"
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["notificationMethod"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["totalChunks"],
        2
    );
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 2);
    assert_eq!(
        notifications[0]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(notifications[0]["params"]["requestId"], json!(2));
    assert_eq!(notifications[0]["params"]["chunkIndex"], 0);
    assert_eq!(notifications[0]["params"]["totalChunks"], 2);
    assert_eq!(notifications[0]["params"]["chunk"]["text"], "chunk one");
    assert_eq!(notifications[1]["params"]["chunkIndex"], 1);
    assert_eq!(notifications[1]["params"]["chunk"]["text"], "chunk two");
}

#[test]
fn tools_call_streams_collapse_when_peer_does_not_negotiate_extension() {
    let mut edge = make_streaming_edge(10);
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

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stream_file", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["mode"],
        "collapsed_result"
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["chunks"][0]["text"],
        "chunk one"
    );
    assert!(edge.take_pending_notifications().is_empty());
}

#[test]
fn incomplete_streamed_tools_call_preserves_chunks_and_terminal_state() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioToolStreaming": {
                        "toolCallChunkNotifications": true
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stream_file_incomplete", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["terminalState"],
        "incomplete"
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["reason"],
        "upstream stream interrupted"
    );

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 2);
    assert_eq!(
        notifications[0]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
}

#[test]
fn task_augmented_tool_call_completes_via_tasks_result_and_tracks_status() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioToolStreaming": {
                        "toolCallChunkNotifications": true
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": { "ttl": 60000 }
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(create["result"]["task"]["status"], "working");
    assert_eq!(create["result"]["task"]["ttl"], 60000);
    assert_eq!(
        create["result"]["task"]["pollInterval"],
        TASK_POLL_INTERVAL_MILLIS
    );
    assert_eq!(create["result"]["task"]["ownership"]["workOwner"], "task");
    assert_eq!(
        create["result"]["task"]["ownership"]["resultStreamOwner"],
        "request_stream"
    );
    assert_eq!(
        create["result"]["task"]["ownership"]["statusNotificationOwner"],
        "session_notification_stream"
    );
    assert_eq!(
        create["result"]["task"]["ownership"]["terminalStateOwner"],
        "task"
    );
    assert!(create["result"]["task"]["ownerSessionId"]
        .as_str()
        .unwrap()
        .starts_with("sess-"));
    assert!(create["result"]["task"]["ownerRequestId"]
        .as_str()
        .unwrap()
        .starts_with("mcp-edge-req-"));
    assert!(create["result"]["task"]["parentRequestId"].is_null());

    let get_working = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(get_working["result"]["status"], "working");
    assert_eq!(get_working["result"]["ownership"]["workOwner"], "task");

    let result = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerSessionId"]
            .as_str()
            .unwrap()
            .starts_with("sess-")
    );
    assert!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"]
            .as_str()
            .unwrap()
            .starts_with("mcp-edge-req-")
    );
    assert!(result["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"].is_null());
    assert_eq!(
        result["result"]["structuredContent"]["chioToolStream"]["mode"],
        "notification_stream"
    );

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 3);
    assert_eq!(
        notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert!(notifications.iter().any(|notification| {
        notification["method"] == "notifications/tasks/status"
            && notification["params"]["taskId"] == task_id
            && notification["params"]["status"] == "completed"
    }));

    let get_completed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(get_completed["result"]["status"], "completed");
    assert_eq!(
        get_completed["result"]["ownership"]["terminalStateOwner"],
        "task"
    );
}

#[test]
fn task_with_zero_ttl_expires_before_get() {
    let mut edge = make_streaming_edge(10);
    edge.set_session_auth_context(SessionAuthContext::streamable_http_static_bearer(
        "agent",
        "fingerprint",
        None,
    ));
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

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": { "ttl": 0 }
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();

    let get = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }))
        .unwrap();

    assert!(get["error"]["message"]
        .as_str()
        .unwrap()
        .contains("task not found"));
}

#[test]
fn task_creation_rejects_ttl_above_edge_retention_ceiling() {
    let mut edge = make_streaming_edge(10);
    edge.set_session_auth_context(SessionAuthContext::streamable_http_static_bearer(
        "agent",
        "fingerprint",
        None,
    ));
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

    let rejected = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": { "ttl": u64::MAX }
            }
        }))
        .unwrap();

    assert_eq!(rejected["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(rejected["error"]["message"], "task ttl exceeds maximum");

    let listed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/list",
            "params": {}
        }))
        .unwrap();
    assert_eq!(listed["result"]["tasks"], json!([]));
}

#[test]
fn task_creation_rejects_deferred_task_map_over_cap() {
    let mut edge = make_streaming_edge(10);
    edge.set_session_auth_context(SessionAuthContext::streamable_http_static_bearer(
        "agent",
        "fingerprint",
        None,
    ));
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

    for index in 0..1_024 {
        let create = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": index + 10,
                "method": "tools/call",
                "params": {
                    "name": "stream_file",
                    "arguments": {},
                    "task": {}
                }
            }))
            .unwrap();
        assert_eq!(create["result"]["task"]["status"], "working");
    }

    let rejected = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2_000,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }))
        .unwrap();

    assert!(rejected["error"]["message"]
        .as_str()
        .unwrap()
        .contains("too many deferred tasks"));
}

#[test]
fn task_methods_reject_malformed_task_ids_before_lookup() {
    let mut edge = make_streaming_edge(10);
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

    for (index, method, task_id) in [
        (10, "tasks/get", ""),
        (11, "tasks/result", " mcp-edge-task-1"),
        (12, "tasks/cancel", "mcp-edge-task-1\n"),
    ] {
        let rejected = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": index,
                "method": method,
                "params": { "taskId": task_id }
            }))
            .unwrap();

        assert_eq!(rejected["error"]["code"], JSONRPC_INVALID_PARAMS);
        assert_eq!(
            rejected["error"]["message"],
            "taskId must be a non-empty unpadded string without control characters"
        );
    }
}

#[test]
fn tasks_cancel_marks_working_task_cancelled_and_result_returns_error_payload() {
    let mut edge = make_streaming_edge(10);
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

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();

    let cancelled = edge
        .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/cancel",
                "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(cancelled["result"]["status"], "cancelled");
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/tasks/status");
    assert_eq!(notifications[0]["params"]["taskId"], task_id);
    assert!(notifications[0]["params"].get("_meta").is_none());

    let result = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
}

#[test]
fn request_cancelled_errors_record_cancelled_task_terminal_state() {
    let _metrics_guard = metrics_test_guard();
    let cancellation = KernelError::RequestCancelled {
        request_id: chio_core::session::RequestId::new("cancelled-request"),
        reason: "cancelled by client: user aborted sample".to_string(),
    };
    assert_kernel_error_not_counted_as_receipt_write(&cancellation);
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

    let (session_id, context, operation) = edge
        .prepare_tool_call_request(
            &json!(2),
            &json!({
                "name": "read_file",
                "arguments": { "path": "/tmp/race" },
                "task": {}
            }),
        )
        .unwrap();
    let task_id = "mcp-edge-task-cancelled".to_string();
    let mut task = EdgeTask::new(task_id.clone(), session_id, context, operation, None, 0);

    let outcome =
        edge.tool_call_error_outcome(&task.session_id, cancellation, Some(task_id.as_str()));
    task.record_outcome(outcome);

    assert_eq!(task.status, EdgeTaskStatus::Cancelled);
    assert_eq!(
        task.status_message.as_deref(),
        Some("cancelled by client: user aborted sample")
    );

    let result = task_outcome_to_jsonrpc(Some(task.clone()), &json!(3), &task_id);
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerSessionId"],
        task.owner_session_id
    );
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"],
        task.owner_request_id
    );
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"].as_str(),
        task.parent_request_id.as_deref()
    );
    assert!(result["result"]["content"][0]["text"]
        .as_str()
        .expect("cancelled task result text")
        .contains("cancelled by client: user aborted sample"));
}

#[test]
fn serve_stdio_handles_initialize_and_tools_list_roundtrip() {
    let mut edge = make_edge(10);
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
    );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert!(tools.iter().all(|tool| tool["name"] != "write_file"));
}

#[test]
fn serve_stdio_malformed_initialized_notification_does_not_enter_ready_state() {
    let mut edge = make_edge(10);
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":[]}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
    );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        responses[1]["error"]["code"],
        JSONRPC_SERVER_NOT_INITIALIZED
    );
    assert!(matches!(
        edge.state,
        EdgeState::WaitingForInitialized { .. }
    ));
}

#[test]
fn serve_stdio_emits_stream_chunk_notifications_before_final_tool_response() {
    let mut edge = make_streaming_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"experimental\":{\"chioToolStreaming\":{\"toolCallChunkNotifications\":true}}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"stream_file\",\"arguments\":{}}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 4);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        responses[1]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(responses[1]["params"]["chunkIndex"], 0);
    assert_eq!(
        responses[2]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(responses[2]["params"]["chunkIndex"], 1);
    assert_eq!(responses[3]["id"], 2);
    assert_eq!(
        responses[3]["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["mode"],
        "notification_stream"
    );
}

#[test]
fn serve_stdio_tasks_result_emits_stream_chunk_notifications_before_result() {
    let mut edge = make_streaming_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"experimental\":{\"chioToolStreaming\":{\"toolCallChunkNotifications\":true}}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"stream_file\",\"arguments\":{},\"task\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tasks/result\",\"params\":{\"taskId\":\"mcp-edge-task-1\"}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 6);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(responses[1]["result"]["task"]["status"], "working");
    assert_eq!(
        responses[2]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(
        responses[3]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(responses[4]["method"], "notifications/tasks/status");
    assert_eq!(responses[4]["params"]["status"], "completed");
    assert_eq!(responses[5]["id"], 3);
    assert_eq!(
        responses[5]["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        "mcp-edge-task-1"
    );
}

#[test]
fn serve_message_channels_matches_stdio_for_streaming_tasks_result_flow() {
    let messages = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "experimental": {
                        "chioToolStreaming": {
                            "toolCallChunkNotifications": true
                        }
                    }
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/result",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }),
    ];

    let mut stdio_edge = make_streaming_edge(10);
    let mut stdio = run_stdio_session(&mut stdio_edge, &messages);
    let mut channel_edge = make_streaming_edge(10);
    let mut channel = run_channel_session(&mut channel_edge, &messages);

    normalize_transport_output(&mut stdio);
    normalize_transport_output(&mut channel);

    assert_eq!(channel, stdio);
}

#[test]
fn serve_message_channels_matches_stdio_for_task_cancellation_flow() {
    let messages = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/cancel",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }),
    ];

    let mut stdio_edge = make_streaming_edge(10);
    let mut stdio = run_stdio_session(&mut stdio_edge, &messages);
    let mut channel_edge = make_streaming_edge(10);
    let mut channel = run_channel_session(&mut channel_edge, &messages);

    normalize_transport_output(&mut stdio);
    normalize_transport_output(&mut channel);

    assert_eq!(channel, stdio);
}

#[test]
fn channel_pump_does_not_signal_notification_shaped_tasks_cancel() {
    let (client_tx, client_rx) = mpsc::channel();
    let (inbound_tx, inbound_rx) = mpsc::channel();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let pump = std::thread::spawn(move || pump_channel_messages(client_rx, inbound_tx, cancel_tx));

    client_tx
        .send(json!({
            "jsonrpc": "2.0",
            "method": "tasks/cancel",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }))
        .unwrap();

    let inbound = inbound_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("pump did not forward inbound message: {error}"));
    match inbound {
        ClientInbound::Message(message) => {
            assert_eq!(message["method"], "tasks/cancel");
            assert!(message.get("id").is_none());
        }
        ClientInbound::ParseError(_) | ClientInbound::ReadError(_) | ClientInbound::Closed => {
            panic!("expected forwarded message")
        }
    }
    assert!(
        cancel_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "notification-shaped tasks/cancel entered the cancellation side channel"
    );

    drop(client_tx);
    pump.join()
        .unwrap_or_else(|_| panic!("channel pump thread panicked"));
}

#[test]
fn stdio_pump_rejects_delimiterless_jsonrpc_frame() {
    let (inbound_tx, inbound_rx) = mpsc::channel();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
    let pump = std::thread::spawn(move || {
        pump_client_messages(Cursor::new(&input[..]), inbound_tx, cancel_tx)
    });

    let inbound = inbound_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("pump did not report parse error: {error}"));
    match inbound {
        ClientInbound::ParseError(message) => {
            assert!(message.contains("newline delimiter"));
        }
        ClientInbound::Message(_) | ClientInbound::ReadError(_) | ClientInbound::Closed => {
            panic!("expected parse error for delimiterless frame")
        }
    }
    assert!(
        cancel_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "delimiterless frame entered cancellation side channel"
    );

    pump.join()
        .unwrap_or_else(|_| panic!("stdio pump thread panicked"));
}

#[test]
fn stdio_pump_rejects_oversized_jsonrpc_frame() {
    let (inbound_tx, inbound_rx) = mpsc::channel();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let input = format!("{}\n", "x".repeat(framing::MAX_STDIO_MCP_FRAME_BYTES + 1));
    let pump = std::thread::spawn(move || {
        pump_client_messages(Cursor::new(input.into_bytes()), inbound_tx, cancel_tx)
    });

    let inbound = inbound_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("pump did not report oversized frame: {error}"));
    match inbound {
        ClientInbound::ParseError(message) => {
            assert!(message.contains("exceeded"));
        }
        ClientInbound::Message(_) | ClientInbound::ReadError(_) | ClientInbound::Closed => {
            panic!("expected parse error for oversized frame")
        }
    }
    assert!(
        cancel_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "oversized frame entered cancellation side channel"
    );

    pump.join()
        .unwrap_or_else(|_| panic!("stdio pump thread panicked"));
}

#[test]
fn read_jsonrpc_line_rejects_delimiterless_frame() {
    let mut reader = Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
    let err = read_jsonrpc_line(&mut reader).unwrap_err();
    assert!(
        matches!(err, AdapterError::ParseError(ref message) if message.contains("newline delimiter")),
        "expected delimiter parse error, got: {err}"
    );
}

#[test]
fn resources_list_is_filtered_by_capabilities() {
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

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }))
        .unwrap();

    let resources = response["result"]["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"], "repo://docs/architecture");
}

#[test]
fn resources_read_returns_contents() {
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

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "repo://docs/architecture" }
        }))
        .unwrap();

    assert_eq!(response["result"]["contents"][0]["text"], "# Architecture");
}

#[test]
fn resources_read_allows_in_root_filesystem_resources() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
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

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    edge.kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/project/docs/architecture.md" }
        }))
        .unwrap();

    assert_eq!(
        response["result"]["contents"][0]["text"],
        "# Filesystem Architecture"
    );
}

#[test]
fn resources_read_denies_out_of_root_filesystem_resources() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
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

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    edge.kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/private/ops.md" }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
            response["error"]["message"],
            "resource read denied: filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
        );
    let receipt = &response["error"]["data"]["receipt"];
    assert_eq!(receipt["tool_name"], "resources/read");
    assert_eq!(receipt["tool_server"], "session");
    assert_eq!(receipt["decision"]["verdict"], "deny");
    assert_eq!(receipt["decision"]["guard"], "session_roots");
    assert_eq!(
        receipt["decision"]["reason"],
        "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
    );
    assert!(receipt["signature"].is_string());
}

#[test]
fn resources_read_denies_filesystem_resources_when_roots_are_missing() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
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

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/project/docs/architecture.md" }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
        response["error"]["message"],
        "resource read denied: no enforceable filesystem roots are available for this session"
    );
    let receipt = &response["error"]["data"]["receipt"];
    assert_eq!(receipt["tool_name"], "resources/read");
    assert_eq!(receipt["tool_server"], "session");
    assert_eq!(receipt["decision"]["verdict"], "deny");
    assert_eq!(receipt["decision"]["guard"], "session_roots");
    assert_eq!(
        receipt["decision"]["reason"],
        "no enforceable filesystem roots are available for this session"
    );
    assert!(receipt["signature"].is_string());
}

#[test]
fn resources_subscribe_tracks_session_state() {
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

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        true
    );
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "repo://docs/architecture" }
        }))
        .unwrap();

    assert_eq!(response["result"], json!({}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    assert!(edge
        .kernel
        .session_has_resource_subscription(&session_id, "repo://docs/architecture")
        .unwrap());
}
