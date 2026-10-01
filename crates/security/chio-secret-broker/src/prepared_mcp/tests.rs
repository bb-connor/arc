use std::io::{Cursor, Read};
use std::time::Duration;

use chio_core_types::canonical_json_bytes;
use chio_test_support::prelude::*;
use serde_json::{json, Value};

use super::*;
use crate::protocol::{BrokerExecuteRequest, BrokerExecuteResponse};
use crate::service::{
    decode_canonical_ipc_request, read_bounded_frame, write_bounded_frame, IpcOperation,
    IpcResponse,
};

const SIGNER: &str = "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff";

fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/security/broker/positive")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).test_expect("read vector"))
        .test_expect("decode vector")
}

fn config() -> PreparedBrokerMcpConfig {
    PreparedBrokerMcpConfig::new(
        "tenant-production".into(),
        "send".into(),
        PublicKey::from_hex(SIGNER).test_expect("signer"),
    )
    .test_expect("public tool config")
}

fn pair() -> (UnixStream, UnixStream) {
    let (client, server) = UnixStream::pair().test_expect("broker pair");
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .test_expect("read deadline");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .test_expect("write deadline");
    }
    (client, server)
}

fn handshake() -> Vec<Value> {
    vec![
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"chio-mcp-adapter", "version":"0.1.0"}}}),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized", "params":{}}),
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
    ]
}

fn call(request: &BrokerExecuteRequest) -> Value {
    json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"send", "arguments":request, "_meta":{"chioOperationId":"original-host-operation"}}})
}

fn lines(messages: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for message in messages {
        serde_json::to_writer(&mut bytes, message).test_expect("MCP frame");
        bytes.push(b'\n');
    }
    bytes
}

#[test]
fn original_prepared_stream_executes_once_and_returns_only_signed_structured_content() {
    let request: BrokerExecuteRequest = fixture("broker-execute-request-v1.json");
    let response: BrokerExecuteResponse = fixture("broker-execute-response-v2.json");
    let envelope = canonical_json_bytes(&IpcResponse {
        operation: IpcOperation::Execute,
        accepted: true,
        response: canonical_json_bytes(&response).test_expect("signed completion"),
        error_code: None,
    })
    .test_expect("broker envelope");
    let (client, mut server) = pair();
    let peer = std::thread::spawn(move || {
        let request = read_bounded_frame(&mut server).test_expect("one original execute");
        write_bounded_frame(&mut server, &envelope).test_expect("signed reply");
        let mut extra = Vec::new();
        server
            .read_to_end(&mut extra)
            .test_expect("socket closes after execute");
        assert!(
            extra.is_empty(),
            "a second call must never reach the broker"
        );
        request
    });
    let mut messages = handshake();
    messages.extend([call(&request), call(&request)]);
    let mut output = Vec::new();
    serve_prepared_broker_mcp(config(), client, Cursor::new(lines(&messages)), &mut output)
        .test_expect("prepared MCP delivery");
    let observed = decode_canonical_ipc_request(&peer.join().test_expect("peer"))
        .test_expect("original broker frame");
    assert_eq!(observed.operation, IpcOperation::Execute);
    assert_eq!(observed.tenant_scope, "tenant-production");
    let observed: BrokerExecuteRequest =
        serde_json::from_slice(&observed.payload).test_expect("original signed request");
    assert_eq!(observed, request);
    let replies: Vec<Value> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).test_expect("MCP response"))
        .collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[1]["result"]["tools"][0]["name"], "send");
    assert_eq!(
        replies[2],
        json!({"jsonrpc":"2.0", "id":3, "result":{"content":[], "structuredContent":response, "isError":false}})
    );
}

#[test]
fn missing_handshake_or_wrong_tool_closes_without_any_broker_request() {
    let request: BrokerExecuteRequest = fixture("broker-execute-request-v1.json");
    let mut wrong_tool = handshake();
    let mut invocation = call(&request);
    invocation["params"]["name"] = json!("another-tool");
    wrong_tool.push(invocation);
    for messages in [vec![call(&request)], wrong_tool] {
        let (client, mut peer) = pair();
        assert!(serve_prepared_broker_mcp(
            config(),
            client,
            Cursor::new(lines(&messages)),
            Vec::new()
        )
        .is_err());
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed)
            .test_expect("refused socket closes");
        assert!(observed.is_empty());
    }
}

#[test]
fn malformed_or_oversized_stdio_never_reaches_the_broker() {
    for bytes in [
        b"{not-json}\n".to_vec(),
        vec![b'x'; crate::protocol::MAX_WIRE_BYTES + 1],
    ] {
        let (client, mut peer) = pair();
        assert!(
            serve_prepared_broker_mcp(config(), client, Cursor::new(bytes), Vec::new()).is_err()
        );
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed)
            .test_expect("refused socket closes");
        assert!(observed.is_empty());
    }
}
