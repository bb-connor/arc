use super::*;
use chio_core::receipt::body::ChioReceipt;

fn call(id: u64, include: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":"echo_json","arguments":{},
        "_meta":{"chioIncludeReceipt":include,"chioRequestId":format!("export-{id}")}
    }})
}

fn verify_envelope(response: &Value, request_id: &str) -> ChioReceipt {
    let envelope = &response["result"]["_meta"]["chioReceipt"];
    assert_eq!(envelope["version"], 1, "{response}");
    let receipt: ChioReceipt = serde_json::from_value(envelope["receipt"].clone()).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(&envelope["output"]).unwrap())
    );
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["receipt_context"]["request_id"],
        request_id
    );
    receipt
}

#[test]
fn requested_receipts_bind_the_actual_kernel_result_and_request() {
    for transport in [false, true] {
        let mut edge = make_edge(10);
        let frames = vec![
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"receipt-test","version":"1"}
            }}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            call(2, json!(true)),
        ];
        let responses = if transport {
            run_channel_session(&mut edge, &frames)
        } else {
            run_stdio_session(&mut edge, &frames)
        };
        let response = responses
            .iter()
            .find(|response| response["id"] == 2)
            .unwrap();
        let receipt = verify_envelope(response, "export-2");
        assert!(receipt.is_allowed());
        assert_eq!(
            response["result"]["_meta"]["chioReceipt"]["output"]["temperature"],
            22.5
        );
    }
}

#[test]
fn direct_calls_preserve_opt_in_and_reject_malformed_requests() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    let plain = edge.handle_jsonrpc(call(2, json!(false))).unwrap();
    assert!(plain["result"]["_meta"].get("chioReceipt").is_none());
    let malformed = edge.handle_jsonrpc(call(3, json!("yes"))).unwrap();
    assert_eq!(malformed["error"]["code"], JSONRPC_INVALID_PARAMS);
    let response = edge.handle_jsonrpc(call(4, json!(true))).unwrap();
    assert!(verify_envelope(&response, "export-4").is_allowed());
}

#[test]
fn revoked_calls_export_a_signed_deny_without_claiming_output() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    for capability in &edge.capabilities {
        edge.kernel.revoke_capability(&capability.id).unwrap();
    }
    let response = edge.handle_jsonrpc(call(2, json!(true))).unwrap();
    assert!(verify_envelope(&response, "export-2").is_denied());
    assert_eq!(
        response["result"]["_meta"]["chioReceipt"]["output_kind"],
        "none"
    );
    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn upstream_metadata_cannot_replace_kernel_receipt_evidence() {
    for upstream in [
        json!(null),
        json!("forged"),
        json!({"chioReceipt":"forged","other":1}),
    ] {
        let expected = json!({"version":1,"receipt":{"id":"kernel-receipt"}});
        let result = crate::runtime::receipts::attach_tool_receipt_envelope(
            json!({"content":[],"_meta":upstream}),
            Some(expected.clone()),
        );
        assert_eq!(result["_meta"]["chioReceipt"], expected);
    }
}

#[test]
fn tools_call_jsonrpc_passes_route_selection_metadata_to_runtime_admission() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge_with_route_selection_admission(10);
    initialize_edge(&mut edge);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "routeSelection": {
                        "selectedRouteId": "mcp:task-child-a",
                        "selectedTargetProtocol": "mcp"
                    }
                }
            }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
}
