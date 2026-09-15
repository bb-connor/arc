//! Live discovery of a native MCP server's tool surface for provisioning.
//!
//! The provisioner spawns the exact target it is about to bind, completes the
//! MCP initialize handshake and records the server's `tools/list` as the
//! reviewed surface. The spawn is bounded in time and output, inherits no Chio
//! credential from the provisioning environment, and is torn down before the
//! function returns, so a server that never answers cannot hold the
//! provisioner open.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use super::CliError;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const INITIALIZE_ID: u64 = 1;
const TOOLS_LIST_ID: u64 = 2;
const PROTOCOL_VERSION: &str = "2025-11-25";
const CREDENTIAL_ENVIRONMENT: &[&str] = &[
    "CHIO_AUTH_TOKEN",
    "CHIO_ADMIN_TOKEN",
    "CHIO_MCP_AUTH_TOKEN",
    "CHIO_MCP_ADMIN_TOKEN",
    "CHIO_CONFORMANCE_AUTH_TOKEN",
    "CHIO_CONFORMANCE_ADMIN_TOKEN",
    "CHIO_CONTROL_TOKEN",
    "CHIO_SIDECAR_CONTROL_TOKEN",
    "CHIO_API_PROTECT_CONTROL_TOKEN",
    "CHIO_SIEM_WEBHOOK_BEARER_TOKEN",
    "CHIO_TRUST_SERVICE_TOKEN",
    "CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN",
];

/// Spawn `target` once and return the tool surface it advertises.
pub(super) fn discover_tool_surface(
    target: &Path,
    args: &[String],
    working_directory: &Path,
) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, CliError> {
    let mut command = Command::new(target);
    command
        .args(args)
        .current_dir(working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in CREDENTIAL_ENVIRONMENT {
        command.env_remove(key);
    }
    let child = command.spawn().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to spawn the native MCP target {} for tool discovery: {error}",
            target.display()
        ))
    })?;
    let mut child = DiscoveryChild { child };
    let mut stdin = child.take_stdin()?;
    let stdout = child.take_stdout()?;
    let mut stderr = child.take_stderr()?;

    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": INITIALIZE_ID,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "chio-provisioner", "version": env!("CARGO_PKG_VERSION") }
            }
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": TOOLS_LIST_ID, "method": "tools/list", "params": {} }),
    ];
    if let Err(reason) = requests
        .iter()
        .try_for_each(|request| write_request(&mut stdin, request))
    {
        child.terminate();
        return Err(discovery_error(&reason, &mut stderr));
    }
    drop(stdin);

    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let outcome = read_tools_list(BufReader::new(stdout));
        let _ = sender.send(outcome);
    });
    let outcome = receiver.recv_timeout(DISCOVERY_TIMEOUT);
    child.terminate();
    let _ = reader.join();
    let tools = match outcome {
        Ok(Ok(tools)) => tools,
        Ok(Err(reason)) => {
            return Err(discovery_error(&reason, &mut stderr));
        }
        Err(_) => {
            return Err(discovery_error(
                &format!(
                    "the target did not answer tools/list within {} seconds",
                    DISCOVERY_TIMEOUT.as_secs()
                ),
                &mut stderr,
            ));
        }
    };
    serde_json::from_value(tools).map_err(|error| {
        CliError::cli_other_error(format!(
            "the native MCP target advertised a tools/list result the signed manifest cannot bind: {error}"
        ))
    })
}

fn write_request(stdin: &mut impl Write, request: &Value) -> Result<(), String> {
    let mut line = serde_json::to_vec(request)
        .map_err(|error| format!("failed to encode an MCP discovery request: {error}"))?;
    line.push(b'\n');
    stdin
        .write_all(&line)
        .and_then(|()| stdin.flush())
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::BrokenPipe => {
                "the target closed its input before the MCP handshake".to_string()
            }
            _ => format!("failed to deliver an MCP discovery request to the target: {error}"),
        })
}

/// Read newline-delimited JSON-RPC messages until the `tools/list` response.
///
/// Notifications and unrelated responses are skipped; an error response to
/// either request, a non-JSON line, an oversized line or end of stream fail
/// the discovery.
fn read_tools_list(mut stdout: impl BufRead) -> Result<Value, String> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = stdout
            .by_ref()
            .take(MAX_RESPONSE_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("failed to read the target's response: {error}"))?;
        if read == 0 {
            return Err("the target closed its output before answering tools/list".to_string());
        }
        if line.len() > MAX_RESPONSE_LINE_BYTES {
            return Err(format!(
                "the target sent a message larger than {MAX_RESPONSE_LINE_BYTES} bytes"
            ));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: Value = serde_json::from_slice(&line)
            .map_err(|error| format!("the target sent a line that is not JSON-RPC: {error}"))?;
        let Some(id) = message.get("id").and_then(Value::as_u64) else {
            continue;
        };
        if let Some(error) = message.get("error") {
            let method = if id == INITIALIZE_ID { "initialize" } else { "tools/list" };
            return Err(format!("the target rejected {method}: {error}"));
        }
        if id == TOOLS_LIST_ID {
            return message
                .get("result")
                .and_then(|result| result.get("tools"))
                .cloned()
                .ok_or_else(|| "the tools/list response carries no tools array".to_string());
        }
    }
}

fn discovery_error(reason: &str, stderr: &mut impl Read) -> CliError {
    let mut diagnostic = String::new();
    let _ = stderr.take(MAX_STDERR_BYTES).read_to_string(&mut diagnostic);
    let diagnostic = diagnostic.trim();
    if diagnostic.is_empty() {
        CliError::cli_other_error(format!("native MCP tool discovery failed: {reason}"))
    } else {
        CliError::cli_other_error(format!(
            "native MCP tool discovery failed: {reason}; target stderr: {diagnostic}"
        ))
    }
}

struct DiscoveryChild {
    child: Child,
}

impl DiscoveryChild {
    fn take_stdin(&mut self) -> Result<std::process::ChildStdin, CliError> {
        self.child
            .stdin
            .take()
            .ok_or_else(|| CliError::cli_other_error("discovery target has no stdin".to_string()))
    }

    fn take_stdout(&mut self) -> Result<std::process::ChildStdout, CliError> {
        self.child
            .stdout
            .take()
            .ok_or_else(|| CliError::cli_other_error("discovery target has no stdout".to_string()))
    }

    fn take_stderr(&mut self) -> Result<std::process::ChildStderr, CliError> {
        self.child
            .stderr
            .take()
            .ok_or_else(|| CliError::cli_other_error("discovery target has no stderr".to_string()))
    }

    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for DiscoveryChild {
    fn drop(&mut self) {
        self.terminate();
    }
}
