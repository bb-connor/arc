use super::*;

#[test]
fn failed_session_activation_on_initialized_sends_no_response() {
    let mut edge = make_edge(10);
    edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }))
    .unwrap();
    let EdgeState::WaitingForInitialized { session_id } = edge.state.clone() else {
        panic!("initialize must wait for notifications/initialized");
    };
    edge.kernel.close_session(&session_id).unwrap();

    let initialized = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));
    assert!(initialized.is_none(), "{initialized:?}");
    assert!(matches!(
        edge.state,
        EdgeState::WaitingForInitialized { .. }
    ));

    let tools_list = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .unwrap();
    assert_eq!(tools_list["error"]["code"], JSONRPC_SERVER_NOT_INITIALIZED);
    assert_eq!(
        tools_list["error"]["message"],
        "tools/list requires initialize followed by notifications/initialized"
    );
}

#[test]
fn initialized_before_initialize_is_ignored_and_handshake_still_completes() {
    let mut edge = make_edge(10);
    let early = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));
    assert!(early.is_none());
    assert!(matches!(edge.state, EdgeState::Uninitialized));

    let tools_list = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }))
        .unwrap();
    assert_eq!(tools_list["error"]["code"], JSONRPC_SERVER_NOT_INITIALIZED);

    edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {}
    }))
    .unwrap();
    assert!(edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .is_none());
    assert!(matches!(edge.state, EdgeState::Ready { .. }));

    let repeated = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));
    assert!(repeated.is_none());
    assert!(matches!(edge.state, EdgeState::Ready { .. }));
}

#[test]
fn initialized_sent_as_a_request_is_refused_and_does_not_activate() {
    let mut edge = make_edge(10);
    edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }))
    .unwrap();

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "notifications/initialized"
        }))
        .unwrap();
    assert_eq!(response["id"], 2);
    assert_eq!(response["error"]["code"], JSONRPC_METHOD_NOT_FOUND);
    assert_eq!(response["error"]["message"], "method not found");
    assert!(matches!(
        edge.state,
        EdgeState::WaitingForInitialized { .. }
    ));
}
