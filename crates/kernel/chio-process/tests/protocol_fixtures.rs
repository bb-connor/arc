#![cfg(all(feature = "worker-server", unix))]

//! Pins the worker server to the shared chio.process.v1 conformance corpus
//! that the Python and TypeScript clients also consume.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::worker::{
    WorkerServer, WorkerService, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL,
};
use chio_process::{ProcessRuntime, MAX_STATE_BLOB_BYTES};
use serde_json::{json, Value};
use support::{kernel, root, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const CORPUS: &str = include_str!("../../../../spec/fixtures/chio-process-v1.json");

/// The corpus reference host's tool server: both tools echo their arguments.
struct Echo;

#[async_trait::async_trait]
impl ToolServerConnection for Echo {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        if arguments.get("large") == Some(&json!(true)) {
            return Ok(json!("x".repeat(MAX_RESPONSE_BYTES)));
        }
        Ok(arguments)
    }
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    Ok(value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("corpus field {field} must be a string"))?)
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut output = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    while !rest.is_empty() {
        if rest.starts_with(needle) {
            output.extend_from_slice(replacement);
            rest = rest.get(needle.len()..).unwrap_or_default();
        } else if let Some((first, tail)) = rest.split_first() {
            output.push(*first);
            rest = tail;
        }
    }
    output
}

fn frame(case: &Value, corpus: &Value, credential: &str) -> Result<Vec<u8>> {
    let raw = match case.get("frame").and_then(Value::as_str) {
        Some(frame) => frame.as_bytes().to_vec(),
        None => base64::engine::general_purpose::STANDARD.decode(text(case, "frame_base64")?)?,
    };
    let mut bytes = replace_bytes(
        &raw,
        text(corpus, "fixture_credential")?.as_bytes(),
        credential.as_bytes(),
    );
    if let Some(fill) = case.get("fill") {
        let count = fill
            .get("count")
            .and_then(Value::as_u64)
            .ok_or("fill count must be an integer")?;
        let piece = text(fill, "char")?.repeat(usize::try_from(count)?);
        bytes = replace_bytes(
            &bytes,
            text(corpus, "fill_marker")?.as_bytes(),
            piece.as_bytes(),
        );
    }
    if case.get("terminated") != Some(&Value::Bool(false)) {
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// One request per connection, read up to the response's newline. A host may
/// refuse an oversized frame before reading all of it, so a failed write is
/// not itself a test failure; the response decides.
async fn exchange(socket: &Path, bytes: &[u8], terminated: bool) -> Result<Value> {
    let mut stream = UnixStream::connect(socket).await?;
    let _ = stream.write_all(bytes).await;
    if !terminated {
        stream.shutdown().await?;
    }
    let mut response = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    while !response.ends_with(b"\n") {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(buffer.get(..count).unwrap_or_default()),
            Err(error) if response.is_empty() => return Err(error.into()),
            Err(_) => break,
        }
    }
    if response.len() > MAX_RESPONSE_BYTES || response.last() != Some(&b'\n') {
        return Err(format!("response frame of {} bytes is not bounded", response.len()).into());
    }
    Ok(serde_json::from_slice(&response)?)
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

#[tokio::test]
async fn worker_server_matches_the_shared_protocol_corpus() -> Result {
    let corpus: Value = serde_json::from_str(CORPUS)?;
    assert_eq!(corpus["protocol"], PROTOCOL);
    assert_eq!(corpus["limits"]["max_request_bytes"], MAX_REQUEST_BYTES);
    assert_eq!(corpus["limits"]["max_response_bytes"], MAX_RESPONSE_BYTES);
    assert_eq!(
        corpus["limits"]["max_state_blob_bytes"],
        MAX_STATE_BLOB_BYTES
    );

    let host = &corpus["server"]["reference_host"];
    let max_calls = host["max_calls"]
        .as_u64()
        .ok_or("reference host max_calls must be an integer")?;
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), Box::new(Echo))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let capability = root(&runtime, &kernel, u32::try_from(max_calls)?)?;
    assert_eq!(host["process_id"], "root");
    let service = WorkerService::new(runtime);
    let credential = service.issue_credential("root", capability.expires_at)?;
    let sockets = dir.path().join("sockets");
    support::private_dir(&sockets)?;
    let socket = sockets.join("worker.sock");
    let listener = WorkerServer::bind(&socket, service)?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(listener.serve(async {
        let _ = stopped.await;
    }));

    let mut results = BTreeMap::new();
    let cases = corpus["server"]["cases"]
        .as_array()
        .ok_or("server cases must be an array")?;
    for case in cases {
        let name = text(case, "name")?;
        let terminated = case.get("terminated") != Some(&Value::Bool(false));
        let bytes = frame(case, &corpus, credential.expose_secret())?;
        let response = exchange(&socket, &bytes, terminated).await?;
        assert_eq!(response["protocol"], PROTOCOL, "{name}");
        let expect = &case["expect"];
        if let Some(code) = expect.get("error") {
            assert_eq!(
                response,
                json!({"protocol": PROTOCOL, "ok": false, "error": {"code": code}}),
                "{name}"
            );
            continue;
        }
        assert_eq!(response["ok"], true, "{name}: {response}");
        assert_eq!(
            sorted_keys(&response),
            ["ok", "protocol", "result"],
            "{name}"
        );
        let result = &response["result"];
        if let Some(exact) = expect.get("result") {
            assert_eq!(result, exact, "{name}");
        }
        if let Some(keys) = expect.get("result_keys") {
            let expected: Vec<String> = serde_json::from_value(keys.clone())?;
            assert_eq!(sorted_keys(result), expected, "{name}");
        }
        if let Some(subset) = expect.get("result_subset").and_then(Value::as_object) {
            for (key, value) in subset {
                assert_eq!(&result[key], value, "{name}: {key}");
            }
        }
        if let Some(earlier) = expect.get("same_result_as").and_then(Value::as_str) {
            assert_eq!(results.get(earlier), Some(result), "{name}");
        }
        results.insert(name.to_owned(), result.clone());
    }
    stop.send(()).map_err(|_| "shutdown channel closed")?;
    server.await??;
    Ok(())
}
