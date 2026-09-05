use super::*;

#[test]
fn exhausted_discovery_and_task_lists_omit_cursor_instead_of_sending_null() {
    let mut edge = make_edge(100);
    initialize_edge(&mut edge);
    for method in [
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "tasks/list",
    ] {
        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc":"2.0", "id":2, "method":method, "params":{}
            }))
            .unwrap();
        assert!(response.get("error").is_none(), "{method}: {response}");
        assert!(
            response["result"].get("nextCursor").is_none(),
            "{method}: {response}"
        );
    }
}

#[test]
fn tool_continuation_is_a_string_and_terminal_page_omits_it() {
    let mut edge = make_edge(1);
    initialize_edge(&mut edge);
    let first = edge
        .handle_jsonrpc(json!({
            "jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}
        }))
        .unwrap();
    assert_eq!(first["result"]["nextCursor"], "1");
    let second = edge
        .handle_jsonrpc(json!({
            "jsonrpc":"2.0", "id":3, "method":"tools/list", "params":{"cursor":"1"}
        }))
        .unwrap();
    assert_eq!(second["result"]["tools"].as_array().unwrap().len(), 1);
    assert!(second["result"].get("nextCursor").is_none());
}

#[test]
fn very_large_page_size_does_not_overflow_after_a_cursor() {
    let mut edge = make_edge(usize::MAX);
    initialize_edge(&mut edge);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{"cursor":"1"}
        }))
        .unwrap();
    assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 1);
    assert!(response["result"].get("nextCursor").is_none());
}
