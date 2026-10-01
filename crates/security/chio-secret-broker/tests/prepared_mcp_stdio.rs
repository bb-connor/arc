//! Real stdio executable and inherited socket transfer. These tests do not
//! claim cage enforcement; the native cage suite owns that separate boundary.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use chio_core_types::canonical_json_bytes;
use chio_secret_broker::inherited_fd::PREPARED_BROKER_FD;
use chio_secret_broker::protocol::{BrokerExecuteRequest, BrokerExecuteResponse};
use chio_secret_broker::service::{
    read_bounded_frame, write_bounded_frame, IpcOperation, IpcResponse,
};
use chio_test_support::prelude::*;
use serde_json::{json, Value};

fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/security/broker/positive")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).test_expect("read vector"))
        .test_expect("decode vector")
}

fn command(descriptor: &impl AsRawFd) -> Command {
    let executable = std::env::var_os("CHIO_BROKER_MCP_TOOL")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_chio-broker-mcp").into());
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args([
            "--tenant-scope",
            "tenant-production",
            "--tool-name",
            "send",
            "--receipt-signer",
            "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let source = descriptor.as_raw_fd();
    // SAFETY: after fork, only descriptor syscalls run before exec. The parent
    // keeps source open through spawn; only the child's slot table changes.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, PREPARED_BROKER_FD) < 0
                || libc::fcntl(PREPARED_BROKER_FD, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

fn input() -> Vec<u8> {
    let request: BrokerExecuteRequest = fixture("broker-execute-request-v1.json");
    let call = json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"send", "arguments":request}});
    let messages = [
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":"2025-11-25"}}),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized", "params":{}}),
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
        call.clone(),
        call,
    ];
    let mut bytes = Vec::new();
    for message in messages {
        serde_json::to_writer(&mut bytes, &message).test_expect("MCP request");
        bytes.push(b'\n');
    }
    bytes
}

#[test]
fn executable_preserves_one_broker_dispatch_and_rejects_a_tampered_completion() {
    for tampered in [false, true] {
        let (client, mut server) = UnixStream::pair().test_expect("broker channel");
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .test_expect("read deadline");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .test_expect("write deadline");
        }
        let mut response: BrokerExecuteResponse = fixture("broker-execute-response-v2.json");
        if tampered {
            response.body.extend(b"untrusted-secret-sentinel");
        }
        let envelope = canonical_json_bytes(&IpcResponse {
            operation: IpcOperation::Execute,
            accepted: true,
            response: canonical_json_bytes(&response).test_expect("signed response"),
            error_code: None,
        })
        .test_expect("response envelope");
        let peer = std::thread::spawn(move || {
            read_bounded_frame(&mut server).test_expect("one original execution");
            write_bounded_frame(&mut server, &envelope).test_expect("return completion");
            let mut extra = Vec::new();
            server
                .read_to_end(&mut extra)
                .test_expect("tool closes socket");
            assert!(extra.is_empty(), "queued replay must not reach broker");
        });
        let mut child = command(&client)
            .spawn()
            .test_expect("start actual MCP executable");
        drop(client);
        child
            .stdin
            .take()
            .test_expect("stdin pipe")
            .write_all(&input())
            .test_expect("write stdio requests");
        let output = child
            .wait_with_output()
            .test_expect("stdio executable exit");
        peer.join().test_expect("broker peer");
        assert_eq!(output.status.success(), !tampered, "{:?}", output.stderr);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("untrusted-secret-sentinel"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("untrusted-secret-sentinel"));
        let replies: Vec<Value> = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).test_expect("MCP result"))
            .collect();
        if tampered {
            assert_eq!(
                replies.len(),
                2,
                "no completion may escape signature verification"
            );
        } else {
            assert_eq!(replies.len(), 3);
            assert_eq!(
                replies[2]["result"]["structuredContent"],
                serde_json::to_value(response).test_expect("response value")
            );
            assert_eq!(replies[2]["result"]["content"], json!([]));
        }
    }
}

#[test]
fn executable_refuses_an_inherited_regular_file_without_mcp_output() {
    let file = tempfile::tempfile().test_expect("non-socket descriptor");
    let output = command(&file)
        .output()
        .test_expect("start with invalid descriptor");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).test_expect("diagnostic"),
        "chio-broker-mcp failed closed: custody\n"
    );
}
