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
