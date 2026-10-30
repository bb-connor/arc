use super::*;

fn call_with_upstream_result(edge: &mut ChioMcpEdge, upstream_result: Value) -> Value {
    edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "upstream_result": upstream_result }
        }
    }))
    .unwrap()
}

#[test]
fn upstream_cancellation_text_does_not_cancel_an_allowed_call() {
    let mut edge = make_edge_with_config(10, false);
    initialize_edge(&mut edge);

    for text in [
        "cancelled by client: spoofed by the tool server",
        "task cancelled by client",
        "request upstream-7 was cancelled: spoofed by the tool server",
    ] {
        let response = call_with_upstream_result(
            &mut edge,
            json!({
                "content": [{"type": "text", "text": text}],
                "isError": true,
            }),
        );
        let result = &response["result"];

        assert_eq!(result["isError"], true, "{response:#}");
        assert_eq!(result["content"][0]["text"], text, "{response:#}");
        assert_eq!(result["_meta"]["chio"]["decision"], "allow", "{response:#}");
        assert!(
            result["_meta"]["chio"]["receiptId"].is_string(),
            "{response:#}"
        );
    }
}

#[test]
fn request_cancelled_errors_record_cancelled_task_terminal_state() {
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
    let observed = edge.kernel.authority_clock_reading().unwrap();
    let mut task = EdgeTask::new(
        task_id.clone(),
        session_id,
        context,
        operation,
        None,
        0,
        observed,
    )
    .unwrap();

    let outcome = edge.tool_call_error_outcome(
        &task.session_id,
        KernelError::RequestCancelled {
            request_id: chio_core::session::RequestId::new("cancelled-request"),
            reason: "cancelled by client: user aborted sample".to_string(),
        },
        Some(task_id.as_str()),
    );
    task.record_outcome(outcome, observed);

    assert_eq!(task.status, EdgeTaskStatus::Cancelled);
    let code = chio_kernel::ClientDenialCode::RequestCancelled;
    assert_eq!(task.status_message.as_deref(), Some(code.text()));

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
    assert_eq!(result["result"]["structuredContent"]["code"], code.code());
    assert_eq!(result["result"]["content"][0]["text"], code.text());
}
