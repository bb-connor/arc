//! Hold a fully written response until natural exit has been recorded.
use super::*;
use chio_test_support::prelude::*;

struct HeldResponse {
    reader: std::process::ChildStdout,
    seen: Vec<u8>,
    entered: Option<mpsc::SyncSender<()>>,
    release: mpsc::Receiver<()>,
}

impl Read for HeldResponse {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let size = self.reader.read(buffer)?;
        if self.entered.is_some() {
            self.seen.extend_from_slice(&buffer[..size]);
            if self
                .seen
                .windows(19)
                .any(|part| part == b"response-after-exit")
            {
                if let Some(entered) = self.entered.take() {
                    entered.send(()).map_err(std::io::Error::other)?;
                    self.release
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(std::io::Error::other)?;
                }
            }
        }
        Ok(size)
    }
}

#[test]
fn completed_response_is_delivered_after_child_exit_before_stdout_decode() {
    let script = r#"
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request.get('method') == 'initialize':
        result = {'protocolVersion':'2025-11-25','capabilities':{'tools':{}},
                  'serverInfo':{'name':'final-response','version':'1'}}
    elif request.get('method') == 'tools/call':
        result = {'content':[], 'structuredContent':{'value':'response-after-exit'}}
    else:
        continue
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}), flush=True)
    if request['method'] == 'tools/call':
        sys.exit(0)
"#;
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let transport = Arc::new(
        StdioMcpTransport::spawn_test_process_with_stdout(
            "python3",
            &["-c", script],
            StdioRequestTimeouts {
                initialization: Duration::from_secs(5),
                discovery: Duration::from_secs(5),
                request: Duration::from_secs(5),
            },
            |reader| {
                Box::new(HeldResponse {
                    reader,
                    seen: Vec::new(),
                    entered: Some(entered_tx),
                    release: release_rx,
                })
            },
        )
        .test_expect("initialize final-response fixture"),
    );
    let request_transport = Arc::clone(&transport);
    let request = std::thread::spawn(move || {
        request_transport.send_request("tools/call", json!({"name":"last", "arguments":{}}))
    });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .test_expect("hold response bytes");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let exited = matches!(
            transport
                .child_lifecycle
                .lock()
                .test_expect("lifecycle lock")
                .terminal,
            ChildTerminalState::Exited
        );
        if exited {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child exit must precede response decoding"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    release_tx.send(()).test_expect("release original response");
    let response = request
        .join()
        .test_expect("request thread")
        .test_expect("original response");
    assert_eq!(
        response["structuredContent"]["value"],
        "response-after-exit"
    );
    assert!(matches!(
        transport.send_request("tools/call", json!({})),
        Err(AdapterError::ConnectionFailed(message)) if message == "upstream MCP process has exited"
    ));
    transport
        .shutdown()
        .test_expect("idempotent terminal shutdown");
}

#[test]
fn natural_child_exit_is_terminalized_once_and_stdout_drain_is_deadline_bounded() {
    let script = r#"
import json
import subprocess
import sys

for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "exit", "version": "1"}
            }
        }) + "\n")
        sys.stdout.flush()
    elif request.get("method") == "tools/call":
        subprocess.Popen([
            sys.executable,
            "-c",
            "import time; time.sleep(1)"
        ])
        sys.exit(17)
"#;
    let transport = StdioMcpTransport::spawn_test_process_with_timeouts(
        "python3",
        &["-c", script],
        StdioRequestTimeouts {
            initialization: Duration::from_secs(10),
            discovery: Duration::from_millis(200),
            request: Duration::from_millis(200),
        },
    )
    .test_expect("initialize natural exit test transport");
    let started = Instant::now();
    let error = transport
        .call_tool("exit", json!({}))
        .test_expect_err("natural child exit must fail the request");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        matches!(&error, AdapterError::ConnectionFailed(message)
            if message == "MCP tools/call request timed out after 200ms"),
        "unexpected natural-exit error: {error}"
    );
    {
        let lifecycle = transport
            .child_lifecycle
            .lock()
            .test_expect("natural exit lifecycle lock");
        assert!(lifecycle.child.is_none());
        assert!(matches!(&lifecycle.terminal, ChildTerminalState::Exited));
    }
    transport
        .shutdown()
        .test_expect("first idempotent shutdown");
    transport
        .shutdown()
        .test_expect("second idempotent shutdown");
}
