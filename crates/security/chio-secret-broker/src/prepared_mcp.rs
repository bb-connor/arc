//! Single-use stdio MCP delivery over an original, host-prepared broker stream.
use std::io::{BufRead, Read, Write};
use std::os::unix::net::UnixStream;

use chio_core_types::PublicKey;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::ipc_client::{BrokerIpcClient, BrokerIpcExecutionOutcome};
use crate::protocol::{BrokerExecuteRequest, MAX_WIRE_BYTES};
use crate::{validate_identifier, BrokerError, Result};

const PROTOCOL_VERSION: &str = "2025-11-25";
const MAX_SESSION_MESSAGES: usize = 16;

/// Public configuration only. The host retains registration and credential keys.
pub struct PreparedBrokerMcpConfig {
    tenant_scope: String,
    tool_name: String,
    receipt_signer: PublicKey,
}

impl PreparedBrokerMcpConfig {
    pub fn new(tenant_scope: String, tool_name: String, receipt_signer: PublicKey) -> Result<Self> {
        validate_identifier(&tenant_scope, "tenant scope", 512)?;
        validate_identifier(&tool_name, "tool name", 128)?;
        Ok(Self {
            tenant_scope,
            tool_name,
            receipt_signer,
        })
    }

    /// The discovery surface to bind into the publisher-signed manifest.
    #[must_use]
    pub fn tool_definition(&self) -> Value {
        json!({
            "name": self.tool_name,
            "description": "Execute one originally admitted request through the credential broker",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false}
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCall {
    name: String,
    arguments: BrokerExecuteRequest,
    // Host provenance is not broker authorization. The prepared stream and
    // original signed request retain that authority.
    #[serde(rename = "_meta", default)]
    _meta: Option<serde_json::Map<String, Value>>,
}

#[derive(PartialEq, Eq)]
enum State {
    New,
    Initialized,
    Ready,
    Listed,
}

/// Consume one prepared stream and at most one tool call. The caller must pass
/// the original authenticated, deadline-bounded stream for this invocation.
/// This server never opens a socket, registers an attempt, or retries a call.
pub fn serve_prepared_broker_mcp(
    config: PreparedBrokerMcpConfig,
    broker: UnixStream,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<()> {
    let mut state = State::New;
    for _ in 0..MAX_SESSION_MESSAGES {
        let message = read_message(&mut input)?;
        if message.jsonrpc != "2.0"
            || message
                .id
                .as_ref()
                .is_some_and(|id| !id.is_string() && id.as_i64().is_none() && id.as_u64().is_none())
        {
            return Err(refused());
        }
        match (message.method.as_str(), &message.id) {
            ("initialize", Some(id)) if state == State::New => {
                if message
                    .params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    != Some(PROTOCOL_VERSION)
                {
                    return Err(refused());
                }
                reply(
                    &mut output,
                    id,
                    json!({
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "chio-broker-mcp", "version": env!("CARGO_PKG_VERSION")}
                    }),
                )?;
                state = State::Initialized;
            }
            ("notifications/initialized", None) if state == State::Initialized => {
                state = State::Ready;
            }
            ("tools/list", Some(id)) if state == State::Ready || state == State::Listed => {
                reply(
                    &mut output,
                    id,
                    json!({"tools": [config.tool_definition()]}),
                )?;
                state = State::Listed;
            }
            ("ping", Some(id)) if state == State::Ready || state == State::Listed => {
                reply(&mut output, id, json!({}))?;
            }
            ("tools/call", Some(id)) if state == State::Listed => {
                let call: ToolCall =
                    serde_json::from_value(message.params).map_err(|_| refused())?;
                if call.name != config.tool_name {
                    return Err(refused());
                }
                // Consuming the stream before returning a result prevents a
                // second request even if a caller queues or replays more input.
                let transcript = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
                    broker,
                    &config.tenant_scope,
                    &call.arguments,
                    &config.receipt_signer,
                )
                .map_err(|error| error.redacted())?;
                let BrokerIpcExecutionOutcome::Success(response) = transcript.outcome else {
                    return Err(refused());
                };
                reply(
                    &mut output,
                    id,
                    json!({"content": [], "structuredContent": response, "isError": false}),
                )?;
                return Ok(());
            }
            _ => return Err(refused()),
        }
    }
    Err(refused())
}

fn read_message(input: &mut impl BufRead) -> Result<Message> {
    let mut frame = Vec::new();
    input
        .take((MAX_WIRE_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .map_err(|_| refused())?;
    if frame.is_empty() || frame.len() > MAX_WIRE_BYTES || frame.last() != Some(&b'\n') {
        return Err(refused());
    }
    serde_json::from_slice(&frame).map_err(|_| refused())
}

fn reply(output: &mut impl Write, id: &Value, result: Value) -> Result<()> {
    serde_json::to_writer(
        &mut *output,
        &json!({"jsonrpc": "2.0", "id": id, "result": result}),
    )
    .map_err(|_| refused())?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|_| refused())
}

fn refused() -> BrokerError {
    BrokerError::AuthorizationDenied("prepared MCP delivery refused".into())
}

#[cfg(test)]
mod tests;
