#[test]
fn mcp_serve_http_get_stream_replays_retained_notifications_and_rejects_stale_cursor() {
    skip_when_loopback_denied!(
        mcp_serve_http_get_stream_replays_retained_notifications_and_rejects_stale_cursor
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let create_task_a = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "task-a" },
                "task": {}
            }
        }),
    );
    let (created_a, created_a_messages) = read_sse_until_response(create_task_a, json!(31), |_| {});
    assert!(created_a_messages.is_empty());
    let task_id_a = created_a["result"]["task"]["taskId"]
        .as_str()
        .expect("task a id")
        .to_string();

    let cancel_a = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tasks/cancel",
            "params": { "taskId": task_id_a }
        }),
    );
    let (_cancelled_a, cancel_a_events) = read_sse_events_until_response(cancel_a, json!(32));
    let first_id = cancel_a_events
        .iter()
        .find_map(|event| event.id.clone())
        .expect("first notification id");

    let create_task_b = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "task-b" },
                "task": {}
            }
        }),
    );
    let (created_b, created_b_messages) = read_sse_until_response(create_task_b, json!(33), |_| {});
    assert!(created_b_messages.is_empty());
    let task_id_b = created_b["result"]["task"]["taskId"]
        .as_str()
        .expect("task b id")
        .to_string();

    let cancel_b = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tasks/cancel",
            "params": { "taskId": task_id_b }
        }),
    );
    let (_cancelled_b, cancel_b_events) = read_sse_events_until_response(cancel_b, json!(34));
    assert!(
        cancel_b_events.iter().any(|event| {
            event.message.as_ref().is_some_and(|message| {
                message["method"] == "notifications/tasks/status"
                    && message["params"]["taskId"].as_str() == Some(task_id_b.as_str())
            })
        }),
        "expected a later retained task status notification"
    );

    let replay = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        Some(&first_id),
    );
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    let mut replay_reader = BufReader::new(replay);
    let replayed = read_next_sse_event(&mut replay_reader).expect("replayed notification");
    let replayed_message = replayed.message.as_ref().expect("replayed message");
    let replayed_method = replayed_message["method"]
        .as_str()
        .expect("replayed method");
    assert_eq!(replayed_method, "notifications/tasks/status");
    assert_eq!(
        replayed_message["params"]["taskId"].as_str(),
        Some(task_id_b.as_str())
    );
    drop(replay_reader);

    for index in 0..70 {
        let overflow = post_json(
            &client,
            &base_url,
            token,
            Some(&session_id),
            Some(&protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 1000 + index,
                "method": "tools/call",
                "params": {
                    "name": "emit_fixture_notifications",
                    "arguments": { "count": 1 }
                }
            }),
        );
        let (_overflow_terminal, _overflow_events) =
            read_sse_events_until_response(overflow, json!(1000 + index));
    }

    let stale_replay = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        Some(&first_id),
    );
    assert_eq!(stale_replay.status(), reqwest::StatusCode::CONFLICT);
}

#[test]
fn mcp_serve_http_get_stream_receives_late_wrapped_notifications_after_post_finishes() {
    skip_when_loopback_denied!(
        mcp_serve_http_get_stream_receives_late_wrapped_notifications_after_post_finishes
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let get_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(get_stream.status(), reqwest::StatusCode::OK);
    let mut get_reader = BufReader::new(get_stream);

    let invoke = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 35,
            "method": "tools/call",
            "params": {
                "name": "emit_late_fixture_notifications",
                "arguments": {
                    "count": 1,
                    "delayMs": 150
                }
            }
        }),
    );
    let (terminal, post_messages) = read_sse_until_response(invoke, json!(35), |_| {});
    assert!(post_messages.is_empty());
    assert!(terminal.get("error").is_none());

    let mut saw_late_resource_event = false;
    for _ in 0..5 {
        let late_event = read_next_sse_event(&mut get_reader).expect("late wrapped notification");
        let Some(late_message) = late_event.message.as_ref() else {
            continue;
        };
        if late_message["method"] == "notifications/resources/list_changed" {
            saw_late_resource_event = true;
            break;
        }
    }
    assert!(
        saw_late_resource_event,
        "expected a late wrapped resources/list_changed notification"
    );
}

#[test]
fn mcp_serve_http_returns_error_when_wrapped_stream_ends_mid_call() {
    skip_when_loopback_denied!(mcp_serve_http_returns_error_when_wrapped_stream_ends_mid_call);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let invoke = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 36,
            "method": "tools/call",
            "params": {
                "name": "drop_stream_mid_call",
                "arguments": {}
            }
        }),
    );
    let (terminal, notifications) = read_sse_until_response(invoke, json!(36), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(terminal["result"]["isError"], true);
    let message = terminal["result"]["content"][0]["text"]
        .as_str()
        .expect("interrupted stream text");
    assert!(
        message.contains("closed stdout")
            || message.contains("process exited")
            || message.contains("upstream stream interrupted"),
        "unexpected interrupted stream error: {message}"
    );
}

#[test]
fn mcp_serve_http_cancels_same_session_tasks_and_blocks_cross_session_cancel() {
    skip_when_loopback_denied!(
        mcp_serve_http_cancels_same_session_tasks_and_blocks_cross_session_cancel
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, protocol_a) = initialize_session(&client, &base_url, token);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, token);

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "cancel me" },
                "task": {}
            }
        }),
    );
    let (created, created_messages) = read_sse_until_response(create_task, json!(40), |_| {});
    assert!(created_messages.is_empty());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let cross_cancel = post_json(
        &client,
        &base_url,
        token,
        Some(&session_b),
        Some(&protocol_b),
        &json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cross_cancel, cross_messages) = read_sse_until_response(cross_cancel, json!(41), |_| {});
    assert!(cross_messages.is_empty());
    assert_eq!(cross_cancel["error"]["code"], -32602);
    assert!(cross_cancel["error"]["message"]
        .as_str()
        .expect("cross-session cancel error")
        .contains("task not found"));

    let cancel_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cancelled, cancel_messages) = read_sse_until_response(cancel_task, json!(42), |_| {});
    assert_eq!(cancelled["result"]["status"], "cancelled");
    assert!(cancel_messages.iter().any(|message| {
        message["method"] == "notifications/tasks/status"
            && message["params"]["taskId"].as_str() == Some(task_id.as_str())
    }));

    let task_result = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tasks/result",
            "params": { "taskId": task_id }
        }),
    );
    let (task_result, task_result_messages) =
        read_sse_until_response(task_result, json!(43), |_| {});
    assert!(task_result_messages.is_empty());
    assert_eq!(task_result["result"]["isError"], true);
}

#[test]
fn mcp_serve_http_shared_hosted_owner_reuses_one_upstream_subprocess_and_keeps_sessions_isolated() {
    skip_when_loopback_denied!(mcp_serve_http_shared_hosted_owner_reuses_one_upstream_subprocess_and_keeps_sessions_isolated);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let startup_marker_path = dir.join("upstream-startups.log");
    let _server = spawn_http_server_with_shared_owner(&dir, listen, token, &startup_marker_path);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, protocol_a) = initialize_session(&client, &base_url, token);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, token);
    let trust_a: Value =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_a)
        .json()
        .expect("session A trust json");
    assert_eq!(
        trust_a["ownership"]["hostedIsolation"].as_str(),
        Some("shared_hosted_owner_compatibility")
    );
    assert_eq!(
        trust_a["ownership"]["hostedIdentityProfile"].as_str(),
        Some("weak_shared_hosted_owner_compatibility")
    );

    let startup_markers =
        fs::read_to_string(&startup_marker_path).expect("read shared owner startup markers");
    let startup_pids = startup_markers
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        startup_pids.len(),
        1,
        "shared hosted owner should reuse one upstream subprocess across sessions"
    );

    let client_a = client.clone();
    let base_url_a = base_url.clone();
    let session_a_for_thread = session_a.clone();
    let protocol_a_for_thread = protocol_a.clone();
    let token_a = token.to_string();
    let slow_a = thread::spawn(move || {
        let response = post_json(
            &client_a,
            &base_url_a,
            &token_a,
            Some(&session_a_for_thread),
            Some(&protocol_a_for_thread),
            &json!({
                "jsonrpc": "2.0",
                "id": 48,
                "method": "tools/call",
                "params": {
                    "name": "slow_echo",
                    "arguments": { "message": "session-a" }
                }
            }),
        );
        read_sse_until_response(response, json!(48), |_| {})
    });

    let client_b = client.clone();
    let base_url_b = base_url.clone();
    let session_b_for_thread = session_b.clone();
    let protocol_b_for_thread = protocol_b.clone();
    let token_b = token.to_string();
    let slow_b = thread::spawn(move || {
        let response = post_json(
            &client_b,
            &base_url_b,
            &token_b,
            Some(&session_b_for_thread),
            Some(&protocol_b_for_thread),
            &json!({
                "jsonrpc": "2.0",
                "id": 49,
                "method": "tools/call",
                "params": {
                    "name": "slow_echo",
                    "arguments": { "message": "session-b" }
                }
            }),
        );
        read_sse_until_response(response, json!(49), |_| {})
    });

    let (slow_a_result, slow_a_events) = slow_a.join().expect("shared owner slow call A");
    let (slow_b_result, slow_b_events) = slow_b.join().expect("shared owner slow call B");
    assert!(slow_a_events.is_empty());
    assert!(slow_b_events.is_empty());
    assert_eq!(slow_a_result["result"]["isError"], false);
    assert_eq!(slow_b_result["result"]["isError"], false);

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "slow_cancelable_echo",
                "arguments": { "message": "shared owner" },
                "task": {}
            }
        }),
    );
    let (created, created_messages) = read_sse_until_response(create_task, json!(50), |_| {});
    assert!(created_messages.is_empty());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let cross_cancel = post_json(
        &client,
        &base_url,
        token,
        Some(&session_b),
        Some(&protocol_b),
        &json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cross_cancel, cross_messages) = read_sse_until_response(cross_cancel, json!(51), |_| {});
    assert!(cross_messages.is_empty());
    assert_eq!(cross_cancel["error"]["code"], -32602);
    assert!(cross_cancel["error"]["message"]
        .as_str()
        .expect("cross-session cancel error")
        .contains("task not found"));

    let task_result = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 52,
            "method": "tasks/result",
            "params": { "taskId": task_id }
        }),
    );
    let (task_result, task_result_messages) =
        read_sse_until_response(task_result, json!(52), |_| {});
    assert!(task_result_messages.iter().any(|message| {
        message["method"] == "notifications/tasks/status"
            && message["params"]["taskId"].as_str() == Some(task_id.as_str())
            && message["params"]["status"].as_str() == Some("completed")
    }));
    assert!(task_result.get("error").is_none());
}

#[test]
fn mcp_serve_http_shared_hosted_owner_broadcasts_global_notifications() {
    skip_when_loopback_denied!(mcp_serve_http_shared_hosted_owner_broadcasts_global_notifications);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let startup_marker_path = dir.join("upstream-startups.log");
    let _server = spawn_http_server_with_shared_owner(&dir, listen, token, &startup_marker_path);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, protocol_a) = initialize_session(&client, &base_url, token);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, token);
    let get_stream_a = get_session_stream(
        &client,
        &base_url,
        token,
        &session_a,
        Some(&protocol_a),
        None,
    );
    assert_eq!(get_stream_a.status(), reqwest::StatusCode::OK);
    let mut get_reader_a = BufReader::new(get_stream_a);
    let get_stream_b = get_session_stream(
        &client,
        &base_url,
        token,
        &session_b,
        Some(&protocol_b),
        None,
    );
    assert_eq!(get_stream_b.status(), reqwest::StatusCode::OK);
    let mut get_reader_b = BufReader::new(get_stream_b);

    let emit_late = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {
                "name": "emit_late_fixture_notifications",
                "arguments": {
                    "count": 1,
                    "delayMs": 150
                }
            }
        }),
    );
    let (terminal, post_messages) = read_sse_until_response(emit_late, json!(60), |_| {});
    assert!(post_messages.is_empty());
    assert!(terminal.get("error").is_none());

    let mut saw_a_notification = false;
    let mut saw_b_notification = false;
    for _ in 0..5 {
        let event_a = read_next_sse_event(&mut get_reader_a).expect("shared owner stream A event");
        if let Some(message) = event_a.message.as_ref() {
            if message["method"] == "notifications/resources/list_changed" {
                saw_a_notification = true;
                break;
            }
        }
    }
    for _ in 0..5 {
        let event_b = read_next_sse_event(&mut get_reader_b).expect("shared owner stream B event");
        if let Some(message) = event_b.message.as_ref() {
            if message["method"] == "notifications/resources/list_changed" {
                saw_b_notification = true;
                break;
            }
        }
    }

    assert!(
        saw_a_notification,
        "expected the originating shared-owner session to receive the late global resources/list_changed notification"
    );
    assert!(
        saw_b_notification,
        "expected every shared-owner session stream to receive the late global resources/list_changed notification"
    );
}

#[test]
fn mcp_serve_http_supports_nested_sampling_over_sse() {
    skip_when_loopback_denied!(mcp_serve_http_supports_nested_sampling_over_sse);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let sampled_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "sample this over HTTP"}
            }
        }),
    );

    let (tool_result, stream_messages) =
        read_sse_until_response(sampled_response, json!(2), |message| {
            if message["method"] == "sampling/createMessage" {
                let follow_up = post_notification(
                    &client,
                    &base_url,
                    token,
                    &session_id,
                    Some(&protocol_version),
                    &json!({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "role": "assistant",
                            "content": {
                                "type": "text",
                                "text": "sampled by http client"
                            },
                            "model": "gpt-test",
                            "stopReason": "end_turn"
                        }
                    }),
                );
                assert_eq!(follow_up.status(), reqwest::StatusCode::ACCEPTED);
            }
        });

    let nested_requests = stream_messages
        .iter()
        .filter(|message| message["method"] == "sampling/createMessage")
        .collect::<Vec<_>>();
    assert_eq!(nested_requests.len(), 1);
    assert_eq!(tool_result["result"]["isError"], false);
    assert_eq!(
        tool_result["result"]["structuredContent"]["sampled"]["content"]["text"],
        "sampled by http client"
    );
}

#[test]
fn mcp_serve_http_parent_cancellation_during_tasks_result_marks_task_cancelled() {
    skip_when_loopback_denied!(
        mcp_serve_http_parent_cancellation_during_tasks_result_marks_task_cancelled
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "cancel this task over HTTP"},
                "task": {}
            }
        }),
    );
    let (created, created_messages) = read_sse_until_response(create_task, json!(60), |_| {});
    assert!(created_messages.is_empty());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let task_result = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 61,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (task_result, task_messages) = read_sse_until_response(task_result, json!(61), |message| {
        if message["method"] == "sampling/createMessage" {
            let cancel = post_notification(
                &client,
                &base_url,
                token,
                &session_id,
                Some(&protocol_version),
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": message["id"],
                        "reason": "user aborted sample"
                    }
                }),
            );
            assert_eq!(cancel.status(), reqwest::StatusCode::ACCEPTED);
        }
    });

    assert_eq!(task_result["result"]["isError"], true);
    assert_eq!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["ownerSessionId"]
            .as_str()
            .expect("owner session id")
            .starts_with("sess-")
    );
    assert!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["ownerRequestId"]
            .as_str()
            .expect("owner request id")
            .starts_with("mcp-edge-req-")
    );
    assert!(task_result["result"]["content"][0]["text"]
        .as_str()
        .expect("cancelled task result text")
        .contains("cancelled by client: user aborted sample"));
    assert!(
        task_messages.iter().any(|message| {
            message["method"] == "notifications/tasks/status"
                && message["params"]["taskId"].as_str() == Some(task_id.as_str())
                && message["params"]["status"].as_str() == Some("cancelled")
        }),
        "missing cancelled task status notification: {task_messages:?}"
    );

    let task_get = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 62,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    let (task_get, task_get_messages) = read_sse_until_response(task_get, json!(62), |_| {});
    assert!(task_get_messages.is_empty());
    assert_eq!(task_get["result"]["status"], "cancelled");
    assert_eq!(
        task_get["result"]["ownership"]["terminalStateOwner"],
        "task"
    );
}

#[test]
fn mcp_serve_http_admin_receipt_queries_return_tool_and_child_receipts() {
    skip_when_loopback_denied!(mcp_serve_http_admin_receipt_queries_return_tool_and_child_receipts);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let echo_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "receipts please"}
            }
        }),
    );
    assert_eq!(echo_response.status(), reqwest::StatusCode::OK);
    let (echo_result, echo_messages) = read_sse_until_response(echo_response, json!(20), |_| {});
    assert!(echo_messages.is_empty());
    assert_eq!(echo_result["result"]["isError"], false);

    let sampled_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "receipt child flow"}
            }
        }),
    );
    let (_sampled_result, _messages) =
        read_sse_until_response(sampled_response, json!(21), |message| {
            if message["method"] == "sampling/createMessage" {
                let follow_up = post_notification(
                    &client,
                    &base_url,
                    token,
                    &session_id,
                    Some(&protocol_version),
                    &json!({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "role": "assistant",
                            "content": {
                                "type": "text",
                                "text": "sample receipt"
                            },
                            "model": "gpt-test",
                            "stopReason": "end_turn"
                        }
                    }),
                );
                assert_eq!(follow_up.status(), reqwest::StatusCode::ACCEPTED);
            }
        });

    let tool_receipts = get_admin_tool_receipts(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &[("tool_name", "echo_json"), ("limit", "10")],
    );
    assert_eq!(tool_receipts.status(), reqwest::StatusCode::OK);
    let tool_receipts: Value = tool_receipts.json().expect("tool receipts json");
    assert_eq!(tool_receipts["backend"], "sqlite");
    let tool_receipts = tool_receipts["receipts"]
        .as_array()
        .expect("tool receipts array");
    assert_eq!(tool_receipts.len(), 1);
    assert_eq!(tool_receipts[0]["tool_name"], "echo_json");
    assert_eq!(tool_receipts[0]["decision"]["verdict"], "allow");

    let child_receipts = get_admin_child_receipts(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &[("operation_kind", "create_message"), ("limit", "10")],
    );
    assert_eq!(child_receipts.status(), reqwest::StatusCode::OK);
    let child_receipts: Value = child_receipts.json().expect("child receipts json");
    assert_eq!(child_receipts["backend"], "sqlite");
    let child_receipts = child_receipts["receipts"]
        .as_array()
        .expect("child receipts array");
    assert_eq!(child_receipts.len(), 1);
    assert_eq!(child_receipts[0]["operation_kind"], "create_message");
    assert!(child_receipts[0]["parent_request_id"].is_string());
}

#[test]
fn mcp_serve_http_admin_revocation_queries_and_direct_revoke_work() {
    skip_when_loopback_denied!(mcp_serve_http_admin_revocation_queries_and_direct_revoke_work);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server admin revocation query",
        |listen| spawn_http_server(&dir, listen, token),
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_id, _protocol_version) = initialize_session(&client, &base_url, token);
    let trust_status =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("trust status json");
    let capability_id = trust_status["capabilities"]
        .as_array()
        .expect("capabilities array")
        .first()
        .and_then(|capability| capability["capabilityId"].as_str())
        .expect("capability id")
        .to_string();

    let before = get_admin_revocations(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &[("capability_id", &capability_id), ("limit", "10")],
    );
    assert_eq!(before.status(), reqwest::StatusCode::OK);
    let before: Value = before.json().expect("revocations json");
    assert_eq!(before["capabilityId"], capability_id);
    assert_eq!(before["revoked"], false);
    assert_eq!(before["count"], 0);

    let revoked = post_admin_capability_revoke(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &capability_id,
    );
    assert_eq!(revoked.status(), reqwest::StatusCode::OK);
    let revoked: Value = revoked.json().expect("revoke json");
    assert_eq!(revoked["capabilityId"], capability_id);
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["newlyRevoked"], true);

    let after = get_admin_revocations(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &[("capability_id", &capability_id), ("limit", "10")],
    );
    assert_eq!(after.status(), reqwest::StatusCode::OK);
    let after: Value = after.json().expect("revocations json");
    assert_eq!(after["revoked"], true);
    assert_eq!(after["count"], 1);
    let entries = after["revocations"].as_array().expect("revocations array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["capabilityId"], capability_id);

    let all = get_admin_revocations(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &[("limit", "10")],
    );
    assert_eq!(all.status(), reqwest::StatusCode::OK);
    let all: Value = all.json().expect("all revocations json");
    let entries = all["revocations"].as_array().expect("revocations array");
    assert!(entries
        .iter()
        .any(|entry| entry["capabilityId"] == capability_id));
}

#[test]
fn mcp_serve_http_admin_revocation_denies_future_calls_for_session() {
    skip_when_loopback_denied!(mcp_serve_http_admin_revocation_denies_future_calls_for_session);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server admin revocation deny",
        |listen| spawn_http_server(&dir, listen, token),
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let trust_status_before =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_id);
    assert_eq!(trust_status_before.status(), reqwest::StatusCode::OK);
    let trust_status_before: Value = trust_status_before.json().expect("trust status json");
    let capabilities_before = trust_status_before["capabilities"]
        .as_array()
        .expect("capabilities array");
    assert!(!capabilities_before.is_empty());
    assert!(capabilities_before
        .iter()
        .all(|capability| capability["revoked"] == false));

    let revoke = post_admin_session_revoke(
        &client,
        &base_url,
        STATIC_AUTH_ADMIN_TOKEN,
        &session_id,
    );
    assert_eq!(revoke.status(), reqwest::StatusCode::OK);
    let revoke_body: Value = revoke.json().expect("revoke json");
    assert_eq!(revoke_body["revoked"], true);
    assert!(
        revoke_body["newlyRevokedCount"]
            .as_u64()
            .expect("newly revoked count")
            >= 1
    );

    let trust_status_after =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_id);
    assert_eq!(trust_status_after.status(), reqwest::StatusCode::OK);
    let trust_status_after: Value = trust_status_after.json().expect("trust status json");
    let capabilities_after = trust_status_after["capabilities"]
        .as_array()
        .expect("capabilities array");
    assert_eq!(capabilities_after.len(), capabilities_before.len());
    assert!(capabilities_after
        .iter()
        .all(|capability| capability["revoked"] == true));

    let denied_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should now be denied"}
            }
        }),
    );
    assert_eq!(denied_response.status(), reqwest::StatusCode::OK);
    let (denied_tool_call, denied_notifications) =
        read_sse_until_response(denied_response, json!(99), |_| {});
    assert!(denied_notifications.is_empty());
    assert_eq!(denied_tool_call["result"]["isError"], true);
    assert!(denied_tool_call["result"]["content"][0]["text"]
        .as_str()
        .expect("denied text")
        .contains("revoked"));
}

#[test]
fn mcp_serve_http_admin_authority_rotation_only_affects_future_sessions() {
    skip_when_loopback_denied!(
        mcp_serve_http_admin_authority_rotation_only_affects_future_sessions
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, _protocol_a) = initialize_session(&client, &base_url, token);

    let authority_before = get_admin_authority(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN);
    assert_eq!(authority_before.status(), reqwest::StatusCode::OK);
    let authority_before: Value = authority_before.json().expect("authority json");
    assert_eq!(authority_before["configured"], true);
    let old_public_key = authority_before["publicKey"]
        .as_str()
        .expect("old authority public key")
        .to_string();

    let trust_a_before =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_a);
    assert_eq!(trust_a_before.status(), reqwest::StatusCode::OK);
    let trust_a_before: Value = trust_a_before.json().expect("session trust json");
    let caps_a_before = trust_a_before["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert!(!caps_a_before.is_empty());
    assert!(caps_a_before.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));

    let rotated = post_admin_rotate_authority(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN);
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: Value = rotated.json().expect("rotated authority json");
    assert_eq!(rotated["rotated"], true);
    assert_eq!(rotated["appliesToFutureSessionsOnly"], true);
    let new_public_key = rotated["publicKey"]
        .as_str()
        .expect("new authority public key")
        .to_string();
    assert_ne!(old_public_key, new_public_key);

    let authority_after = get_admin_authority(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN);
    assert_eq!(authority_after.status(), reqwest::StatusCode::OK);
    let authority_after: Value = authority_after.json().expect("authority json");
    assert_eq!(
        authority_after["publicKey"].as_str(),
        Some(new_public_key.as_str())
    );

    let (session_b, _protocol_b) = initialize_session(&client, &base_url, token);
    let trust_b =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_b);
    assert_eq!(trust_b.status(), reqwest::StatusCode::OK);
    let trust_b: Value = trust_b.json().expect("session trust json");
    let caps_b = trust_b["capabilities"]
        .as_array()
        .expect("session B capabilities");
    assert!(!caps_b.is_empty());
    assert!(caps_b.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(new_public_key.as_str())
    }));

    let trust_a_after =
        get_admin_session_trust(&client, &base_url, STATIC_AUTH_ADMIN_TOKEN, &session_a);
    assert_eq!(trust_a_after.status(), reqwest::StatusCode::OK);
    let trust_a_after: Value = trust_a_after.json().expect("session trust json");
    let caps_a_after = trust_a_after["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert_eq!(caps_a_after.len(), caps_a_before.len());
    assert!(caps_a_after.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));
}

#[test]
fn mcp_serve_http_shared_authority_rotation_propagates_across_nodes() {
    skip_when_loopback_denied!(mcp_serve_http_shared_authority_rotation_propagates_across_nodes);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let authority_db_path = dir.join("shared-authority.sqlite3");
    drop(
        chio_store_sqlite::SqliteCapabilityAuthority::open(&authority_db_path)
            .expect("provision shared capability authority database"),
    );
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen_a, _server_a) = spawn_with_bind_retry(
        &client,
        "shared-authority MCP server A",
        |listen| spawn_http_server_with_authority_db(&dir, listen, token, &authority_db_path),
        wait_for_server_result,
    );
    let (listen_b, _server_b) = spawn_with_bind_retry(
        &client,
        "shared-authority MCP server B",
        |listen| spawn_http_server_with_authority_db(&dir, listen, token, &authority_db_path),
        wait_for_server_result,
    );
    let base_url_a = format!("http://{listen_a}");
    let base_url_b = format!("http://{listen_b}");

    let authority_before = get_admin_authority(&client, &base_url_a, STATIC_AUTH_ADMIN_TOKEN);
    assert_eq!(authority_before.status(), reqwest::StatusCode::OK);
    let authority_before: Value = authority_before.json().expect("authority json");
    assert_eq!(authority_before["backend"], "sqlite");
    let old_public_key = authority_before["publicKey"]
        .as_str()
        .expect("old authority public key")
        .to_string();
    let old_generation = authority_before["generation"]
        .as_u64()
        .expect("old authority generation");

    let (session_a, _protocol_a) = initialize_session(&client, &base_url_a, token);
    let trust_a_before =
        get_admin_session_trust(&client, &base_url_a, STATIC_AUTH_ADMIN_TOKEN, &session_a);
    assert_eq!(trust_a_before.status(), reqwest::StatusCode::OK);
    let trust_a_before: Value = trust_a_before.json().expect("session trust json");
    let caps_a_before = trust_a_before["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert!(!caps_a_before.is_empty());
    assert!(caps_a_before.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));

    let rotated = post_admin_rotate_authority(&client, &base_url_a, STATIC_AUTH_ADMIN_TOKEN);
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: Value = rotated.json().expect("rotated authority json");
    assert_eq!(rotated["backend"], "sqlite");
    let new_public_key = rotated["publicKey"]
        .as_str()
        .expect("new authority public key")
        .to_string();
    let new_generation = rotated["generation"]
        .as_u64()
        .expect("new authority generation");
    assert_ne!(old_public_key, new_public_key);
    assert_eq!(new_generation, old_generation + 1);

    let authority_seen_from_b =
        get_admin_authority(&client, &base_url_b, STATIC_AUTH_ADMIN_TOKEN);
    assert_eq!(authority_seen_from_b.status(), reqwest::StatusCode::OK);
    let authority_seen_from_b: Value = authority_seen_from_b.json().expect("authority json");
    assert_eq!(
        authority_seen_from_b["publicKey"].as_str(),
        Some(new_public_key.as_str())
    );
    assert_eq!(
        authority_seen_from_b["generation"].as_u64(),
        Some(new_generation)
    );

    let (session_b, _protocol_b) = initialize_session(&client, &base_url_b, token);
    let trust_b =
        get_admin_session_trust(&client, &base_url_b, STATIC_AUTH_ADMIN_TOKEN, &session_b);
    assert_eq!(trust_b.status(), reqwest::StatusCode::OK);
    let trust_b: Value = trust_b.json().expect("session trust json");
    let caps_b = trust_b["capabilities"]
        .as_array()
        .expect("session B capabilities");
    assert!(!caps_b.is_empty());
    assert!(caps_b.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(new_public_key.as_str())
    }));

    let trust_a_after =
        get_admin_session_trust(&client, &base_url_a, STATIC_AUTH_ADMIN_TOKEN, &session_a);
    assert_eq!(trust_a_after.status(), reqwest::StatusCode::OK);
    let trust_a_after: Value = trust_a_after.json().expect("session trust json");
    let caps_a_after = trust_a_after["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert_eq!(caps_a_after.len(), caps_a_before.len());
    assert!(caps_a_after.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));
}

#[test]
fn mcp_serve_http_control_service_centralizes_receipts_revocations_and_authority() {
    skip_when_loopback_denied!(
        mcp_serve_http_control_service_centralizes_receipts_revocations_and_authority
    );
    let dir = unique_test_dir();
    let node_a_dir = dir.join("node-a");
    let node_b_dir = dir.join("node-b");
    fs::create_dir_all(&node_a_dir).expect("create node A dir");
    fs::create_dir_all(&node_b_dir).expect("create node B dir");

    let receipt_db_path = dir.join("control-receipts.sqlite3");
    let revocation_db_path = dir.join("control-revocations.sqlite3");
    let authority_db_path = dir.join("control-authority.sqlite3");
    let budget_db_path = dir.join("control-budgets.sqlite3");
    let auth_token = "edge-token";
    let edge_admin_token = "edge-admin-token";
    let control_token = "control-token";
    let authority_admin_token = "authority-admin-token";
    let bootstrap_client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build bootstrap reqwest client");

    let (control_listen, _control) = spawn_with_bind_retry(
        &bootstrap_client,
        "trust control service",
        |listen| {
            spawn_trust_control_service(
                listen,
                control_token,
                authority_admin_token,
                &receipt_db_path,
                &revocation_db_path,
                &authority_db_path,
                &budget_db_path,
            )
        },
        wait_for_control_service_result,
    );
    let control_tls = ControlTlsProxy::spawn(&dir, control_listen);
    let control_base_url = control_tls.base_url().to_string();
    let control_root = reqwest::Certificate::from_pem(
        &fs::read(control_tls.root_ca_path()).expect("read control TLS root CA"),
    )
    .expect("parse control TLS root CA");
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .add_root_certificate(control_root)
        .build()
        .expect("build TLS-aware reqwest client");

    let authority_before = get_control_authority(&client, &control_base_url, control_token);
    assert_eq!(authority_before.status(), reqwest::StatusCode::OK);
    let authority_before: Value = authority_before.json().expect("control authority json");
    assert_eq!(authority_before["configured"], true);
    assert_eq!(authority_before["backend"], "sqlite");
    let old_public_key = authority_before["publicKey"]
        .as_str()
        .expect("old authority public key")
        .to_string();
    let trusted_keys_before = authority_before["trustedPublicKeys"]
        .as_array()
        .expect("initial trusted authority keys")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("initial trusted authority key string")
                .to_string()
        })
        .collect::<Vec<_>>();

    let (listen_a, _server_a) = spawn_with_bind_retry(
        &client,
        "control-backed MCP server A",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_a_dir,
                listen,
                auth_token,
                edge_admin_token,
                &control_base_url,
                control_token,
                &authority_db_path,
                &old_public_key,
                &trusted_keys_before,
                control_tls.root_ca_path(),
            )
        },
        wait_for_server_result,
    );
    let (listen_b, server_b) = spawn_with_bind_retry(
        &client,
        "control-backed MCP server B",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_b_dir,
                listen,
                auth_token,
                edge_admin_token,
                &control_base_url,
                control_token,
                &authority_db_path,
                &old_public_key,
                &trusted_keys_before,
                control_tls.root_ca_path(),
            )
        },
        wait_for_server_result,
    );
    let base_url_a = format!("http://{listen_a}");
    let base_url_b = format!("http://{listen_b}");

    let (session_a, protocol_a) = initialize_session(&client, &base_url_a, auth_token);
    let trust_a_before =
        get_admin_session_trust(&client, &base_url_a, edge_admin_token, &session_a);
    assert_eq!(trust_a_before.status(), reqwest::StatusCode::OK);
    let trust_a_before: Value = trust_a_before.json().expect("session trust json");
    let caps_a_before = trust_a_before["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert!(!caps_a_before.is_empty());
    let capability_id = caps_a_before[0]["capabilityId"]
        .as_str()
        .expect("capability id")
        .to_string();
    assert!(caps_a_before.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));

    let tool_call = post_json(
        &client,
        &base_url_a,
        auth_token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "distributed hello"}
            }
        }),
    );
    assert_eq!(tool_call.status(), reqwest::StatusCode::OK);
    let (tool_call, notifications) = read_sse_until_response(tool_call, json!(41), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(
        tool_call["result"]["structuredContent"]["echo"],
        "distributed hello"
    );

    let control_receipts = get_control_tool_receipts(
        &client,
        &control_base_url,
        control_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(control_receipts.status(), reqwest::StatusCode::OK);
    let control_receipts: Value = control_receipts.json().expect("control receipts json");
    assert_eq!(control_receipts["configured"], true);
    assert_eq!(control_receipts["kind"], "tool");
    assert_eq!(control_receipts["count"], 1);

    let proxied_receipts = get_admin_tool_receipts(
        &client,
        &base_url_b,
        edge_admin_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(proxied_receipts.status(), reqwest::StatusCode::OK);
    let proxied_receipts: Value = proxied_receipts.json().expect("proxied receipts json");
    assert_eq!(proxied_receipts["count"], control_receipts["count"]);
    assert_eq!(
        proxied_receipts["receipts"][0]["tool_name"],
        control_receipts["receipts"][0]["tool_name"]
    );

    let rotated = post_control_rotate_authority(
        &client,
        &control_base_url,
        authority_admin_token,
    );
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: Value = rotated.json().expect("rotated authority json");
    let new_public_key = rotated["publicKey"]
        .as_str()
        .expect("new authority public key")
        .to_string();
    assert_ne!(new_public_key, old_public_key);
    let trusted_keys = rotated["trustedPublicKeys"]
        .as_array()
        .expect("trusted authority keys")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("trusted authority key string")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(trusted_keys.iter().any(|value| value == &old_public_key));
    assert!(trusted_keys.iter().any(|value| value == &new_public_key));

    let tool_call_after_rotation = post_json(
        &client,
        &base_url_a,
        auth_token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "old session still valid"}
            }
        }),
    );
    assert_eq!(tool_call_after_rotation.status(), reqwest::StatusCode::OK);
    let (tool_call_after_rotation, notifications) =
        read_sse_until_response(tool_call_after_rotation, json!(42), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(
        tool_call_after_rotation["result"]["structuredContent"]["echo"],
        "old session still valid"
    );

    let stale_session = post_json(
        &client,
        &base_url_b,
        auth_token,
        None,
        Some("2025-11-25"),
        &json!({
            "jsonrpc": "2.0",
            "id": 91,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "stale-authority-pin",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!(
        stale_session.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let stale_session_error = stale_session.text().expect("stale session error body");
    assert!(stale_session_error
        .contains("local authority/control-pin epoch mismatch during future kernel selection"));

    drop(server_b);
    let (listen_b, _server_b) = spawn_with_bind_retry(
        &client,
        "repinned control-backed MCP server B",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_b_dir,
                listen,
                auth_token,
                edge_admin_token,
                &control_base_url,
                control_token,
                &authority_db_path,
                &new_public_key,
                &trusted_keys,
                control_tls.root_ca_path(),
            )
        },
        wait_for_server_result,
    );
    let base_url_b = format!("http://{listen_b}");

    let (session_b, _protocol_b) = initialize_session(&client, &base_url_b, auth_token);
    let trust_b = get_admin_session_trust(&client, &base_url_b, edge_admin_token, &session_b);
    assert_eq!(trust_b.status(), reqwest::StatusCode::OK);
    let trust_b: Value = trust_b.json().expect("session trust json");
    let caps_b = trust_b["capabilities"]
        .as_array()
        .expect("session B capabilities");
    assert!(!caps_b.is_empty());
    assert!(caps_b.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(new_public_key.as_str())
    }));

    let revoke = post_admin_capability_revoke(
        &client,
        &base_url_b,
        edge_admin_token,
        &capability_id,
    );
    assert_eq!(revoke.status(), reqwest::StatusCode::OK);
    let revoke: Value = revoke.json().expect("revoke capability json");
    assert_eq!(revoke["capabilityId"], capability_id);
    assert_eq!(revoke["revoked"], true);
    assert_eq!(revoke["newlyRevoked"], true);

    let control_revocations = get_control_revocations(
        &client,
        &control_base_url,
        control_token,
        &[("capabilityId", capability_id.as_str()), ("limit", "1")],
    );
    assert_eq!(control_revocations.status(), reqwest::StatusCode::OK);
    let control_revocations: Value = control_revocations
        .json()
        .expect("control revocations json");
    assert_eq!(control_revocations["revoked"], true);
    assert_eq!(control_revocations["count"], 1);

    let denied_response = post_json(
        &client,
        &base_url_a,
        auth_token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should now be denied"}
            }
        }),
    );
    assert_eq!(denied_response.status(), reqwest::StatusCode::OK);
    let (denied_tool_call, denied_notifications) =
        read_sse_until_response(denied_response, json!(43), |_| {});
    assert!(denied_notifications.is_empty());
    assert_eq!(denied_tool_call["result"]["isError"], true);
    assert!(denied_tool_call["result"]["content"][0]["text"]
        .as_str()
        .expect("denied text")
        .contains("revoked"));
}
