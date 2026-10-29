use super::*;
use crate::stateless::{
    JSONRPC_UNSUPPORTED_PROTOCOL_VERSION, MCP_2025_11_25, MCP_2026_07_28, META_SERVER_INFO,
};

fn stateless_request(id: u64, method: &str, mut params: Value, version: &str) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": { "name": "test-client", "version": "1" },
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

#[test]
fn server_discover_lists_both_revisions_without_opening_a_session() {
    let mut edge = make_edge(10);

    let response = edge
        .handle_jsonrpc(stateless_request(
            1,
            "server/discover",
            json!({}),
            MCP_2026_07_28,
        ))
        .unwrap();

    let result = &response["result"];
    assert_eq!(
        result["supportedVersions"],
        json!([MCP_2026_07_28, MCP_2025_11_25])
    );
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["_meta"][META_SERVER_INFO]["name"], "Chio MCP Edge");
    assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
    assert!(result["capabilities"].get("tasks").is_none());
    assert!(result["capabilities"].get("logging").is_none());
    assert!(matches!(edge.state, EdgeState::Uninitialized));
}

#[test]
fn stateless_requests_are_served_without_initialize() {
    let mut edge = make_edge_with_config(10, false);

    let tools = edge
        .handle_jsonrpc(stateless_request(
            1,
            "tools/list",
            json!({}),
            MCP_2026_07_28,
        ))
        .unwrap();
    assert_eq!(tools["result"]["resultType"], "complete");
    assert_eq!(tools["result"]["cacheScope"], "private");
    assert!(tools["result"]["tools"]
        .as_array()
        .is_some_and(|tools| !tools.is_empty()));

    let call = edge
        .handle_jsonrpc(stateless_request(
            2,
            "tools/call",
            json!({ "name": "read_file", "arguments": { "path": "/tmp/demo.txt" } }),
            MCP_2026_07_28,
        ))
        .unwrap();
    assert_eq!(call["result"]["isError"], false);
    assert_eq!(call["result"]["resultType"], "complete");
    assert!(call["result"].get("ttlMs").is_none());

    let session_id = ready_session_id(&edge);
    let peer = edge
        .kernel
        .session(&session_id)
        .map(|session| session.peer_capabilities().clone())
        .unwrap();
    assert!(!peer.supports_roots && !peer.supports_sampling && !peer.supports_elicitation);
}

#[test]
fn unsupported_stateless_revision_is_refused_with_supported_list() {
    let mut edge = make_edge(10);

    for requested in ["1900-01-01", MCP_2025_11_25] {
        let response = edge
            .handle_jsonrpc(stateless_request(1, "tools/list", json!({}), requested))
            .unwrap();
        assert_eq!(
            response["error"]["code"],
            JSONRPC_UNSUPPORTED_PROTOCOL_VERSION
        );
        assert_eq!(response["error"]["data"]["requested"], requested);
        assert_eq!(
            response["error"]["data"]["supported"],
            json!([MCP_2026_07_28, MCP_2025_11_25])
        );
        assert_eq!(
            response["error"]["data"]["chioError"]["code"],
            CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED
        );
    }
    assert!(matches!(edge.state, EdgeState::Uninitialized));
}

#[test]
fn eras_do_not_mix_on_one_edge() {
    let mut handshake = make_edge(10);
    initialize_edge(&mut handshake);
    let refused = handshake
        .handle_jsonrpc(stateless_request(
            2,
            "tools/list",
            json!({}),
            MCP_2026_07_28,
        ))
        .unwrap();
    assert_eq!(refused["error"]["code"], JSONRPC_INVALID_REQUEST);

    let mut stateless = make_edge(10);
    let initialize = stateless
        .handle_jsonrpc(stateless_request(
            1,
            "initialize",
            json!({ "protocolVersion": MCP_2026_07_28 }),
            MCP_2026_07_28,
        ))
        .unwrap();
    assert_eq!(initialize["error"]["code"], JSONRPC_INVALID_REQUEST);

    stateless
        .handle_jsonrpc(stateless_request(
            2,
            "tools/list",
            json!({}),
            MCP_2026_07_28,
        ))
        .unwrap();
    let missing_version = stateless
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}
        }))
        .unwrap();
    assert_eq!(
        missing_version["error"]["code"],
        JSONRPC_UNSUPPORTED_PROTOCOL_VERSION
    );
    let initialize_after = stateless
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}
        }))
        .unwrap();
    assert_eq!(
        initialize_after["error"]["code"],
        JSONRPC_UNSUPPORTED_PROTOCOL_VERSION
    );
}

#[test]
fn methods_removed_by_the_stateless_revision_are_not_found() {
    let mut edge = make_edge(10);
    for method in [
        "ping",
        "logging/setLevel",
        "resources/subscribe",
        "tasks/list",
    ] {
        let response = edge
            .handle_jsonrpc(stateless_request(1, method, json!({}), MCP_2026_07_28))
            .unwrap();
        assert_eq!(
            response["error"]["code"], JSONRPC_METHOD_NOT_FOUND,
            "{method}"
        );
    }

    let task = edge
        .handle_jsonrpc(stateless_request(
            2,
            "tools/call",
            json!({ "name": "read_file", "arguments": {}, "task": {} }),
            MCP_2026_07_28,
        ))
        .unwrap();
    assert_eq!(task["error"]["code"], JSONRPC_INVALID_PARAMS);
}

#[test]
fn initialize_still_selects_the_handshake_revision() {
    let mut edge = make_edge(10);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": MCP_2025_11_25 }
        }))
        .unwrap();
    assert_eq!(response["result"]["protocolVersion"], MCP_2025_11_25);
    assert!(response["result"].get("resultType").is_none());

    let mut edge = make_edge(10);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": MCP_2026_07_28 }
        }))
        .unwrap();
    assert_eq!(response["result"]["protocolVersion"], MCP_2025_11_25);
}

#[test]
fn stateless_tool_results_carry_signed_execution_evidence() {
    let mut edge = make_edge_with_config(10, false);
    let discover = edge
        .handle_jsonrpc(stateless_request(
            1,
            "server/discover",
            json!({}),
            MCP_2026_07_28,
        ))
        .unwrap();
    let advertised =
        &discover["result"]["capabilities"]["experimental"]["io.chio/execution-evidence"];
    assert_eq!(advertised["version"], "1");
    assert_eq!(
        advertised["outputKinds"],
        json!(["value", "stream", "none"])
    );

    let mut request = stateless_request(
        2,
        "tools/call",
        json!({ "name": "read_file", "arguments": { "path": "/tmp/demo.txt" } }),
        MCP_2026_07_28,
    );
    request["params"]["_meta"]["chioRequestId"] = json!("stateless-evidence-2");
    let call = edge.handle_jsonrpc(request).unwrap();
    let meta = &call["result"]["_meta"];
    assert_eq!(meta[META_SERVER_INFO]["name"], "Chio MCP Edge");
    let evidence = &meta["chioEvidence"];
    assert_eq!(evidence["schema"], "chio.mcp.execution-evidence.v1");
    assert_eq!(evidence["requestId"], "stateless-evidence-2");
    assert_eq!(evidence["outputKind"], "value");
    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_value(evidence["receipt"].clone()).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.decision, Some(Decision::Allow));
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["receipt_context"]["request_id"],
        "stateless-evidence-2"
    );
    assert_eq!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(&evidence["output"]).unwrap())
    );
    assert_eq!(meta["chio"]["receiptId"], json!(receipt.id));
}
