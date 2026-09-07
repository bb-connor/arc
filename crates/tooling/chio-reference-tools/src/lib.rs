//! A minimal MCP server over standard input and output for tools that run
//! inside the cage.
//!
//! The server is single-threaded, reads one JSON-RPC object per line, never
//! touches the environment or the network, and bounds every message. A tool
//! implements [`ToolServer`]; the server owns the protocol: `initialize`,
//! `ping`, `tools/list`, `tools/call`, and the notifications a client sends.

use std::fmt;
use std::io::{BufRead, Read, Write};

use serde_json::{json, Value};

/// The MCP protocol revision the tools answer with.
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// The longest request line accepted, in bytes.
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// One tool as `tools/list` advertises it.
#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub read_only: bool,
}

impl ToolDescriptor {
    fn listing(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": { "readOnlyHint": self.read_only },
        })
    }
}

/// What a tool returns: the text the caller reads and, optionally, the
/// same result as structured content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub text: String,
    pub structured: Option<Value>,
}

impl ToolOutput {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            structured: None,
        }
    }

    /// Text and structured content from one JSON value.
    pub fn structured(value: Value) -> Self {
        Self {
            text: value.to_string(),
            structured: Some(value),
        }
    }
}

/// Why a call did not produce output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// The arguments do not match the tool's schema; reported as a JSON-RPC
    /// invalid-params error.
    InvalidArguments(String),
    /// The tool refuses the request under its own policy; reported as a tool
    /// result with `isError`.
    Refused(String),
    /// The request was acceptable but the operation failed; reported as a
    /// tool result with `isError`.
    Failed(String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(reason) => write!(f, "invalid arguments: {reason}"),
            Self::Refused(reason) => write!(f, "refused: {reason}"),
            Self::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

impl std::error::Error for ToolError {}

/// A tool set the server exposes.
pub trait ToolServer {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn tools(&self) -> Vec<ToolDescriptor>;
    fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError>;
}

/// Serve `server` over `input` and `output` until the input ends.
pub fn serve<S: ToolServer>(
    mut server: S,
    mut input: impl BufRead,
    mut output: impl Write,
) -> std::io::Result<()> {
    let mut line = Vec::with_capacity(4096);
    loop {
        line.clear();
        let Some(oversized) = read_line(&mut input, &mut line)? else {
            return Ok(());
        };
        if oversized {
            respond(
                &mut output,
                error_response(
                    Value::Null,
                    PARSE_ERROR,
                    "request line exceeds the size limit",
                ),
            )?;
            continue;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: Value = match serde_json::from_slice(&line) {
            Ok(message) => message,
            Err(error) => {
                respond(
                    &mut output,
                    error_response(
                        Value::Null,
                        PARSE_ERROR,
                        &format!("malformed JSON: {error}"),
                    ),
                )?;
                continue;
            }
        };
        if let Some(response) = handle(&mut server, &message) {
            respond(&mut output, response)?;
        }
    }
}

/// Read one line into `buffer`. `None` at end of input; `Some(true)` when
/// the line exceeded [`MAX_LINE_BYTES`] and was discarded.
fn read_line(input: &mut impl BufRead, buffer: &mut Vec<u8>) -> std::io::Result<Option<bool>> {
    let read = Read::take(&mut *input, MAX_LINE_BYTES as u64 + 1).read_until(b'\n', buffer)?;
    if read == 0 {
        return Ok(None);
    }
    if buffer.len() > MAX_LINE_BYTES {
        let mut discard = Vec::new();
        loop {
            discard.clear();
            let read =
                Read::take(&mut *input, MAX_LINE_BYTES as u64).read_until(b'\n', &mut discard)?;
            if read == 0 || discard.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(true));
    }
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    Ok(Some(false))
}

fn respond(output: &mut impl Write, response: Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *output, &response)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn result_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Handle one message; notifications produce no response.
pub fn handle<S: ToolServer>(server: &mut S, message: &Value) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(error_response(
            Value::Null,
            INVALID_REQUEST,
            "request is not an object",
        ));
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return id.map(|id| error_response(id, INVALID_REQUEST, "request has no method"));
    };
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    let id = id?;
    Some(match method {
        "initialize" => result_response(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": server.name(), "version": server.version() },
            }),
        ),
        "ping" => result_response(id, json!({})),
        "tools/list" => {
            let tools: Vec<Value> = server.tools().iter().map(ToolDescriptor::listing).collect();
            result_response(id, json!({ "tools": tools }))
        }
        "tools/call" => call(server, id, &params),
        _ => error_response(id, METHOD_NOT_FOUND, &format!("unknown method {method}")),
    })
}

fn call<S: ToolServer>(server: &mut S, id: Value, params: &Value) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, INVALID_PARAMS, "tools/call needs a tool name");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !arguments.is_object() {
        return error_response(id, INVALID_PARAMS, "tool arguments must be an object");
    }
    if !server.tools().iter().any(|tool| tool.name == name) {
        return error_response(id, INVALID_PARAMS, &format!("unknown tool {name}"));
    }
    match server.call(name, &arguments) {
        Ok(output) => {
            let mut result = json!({
                "content": [{ "type": "text", "text": output.text }],
                "isError": false,
            });
            if let Some(structured) = output.structured {
                result["structuredContent"] = structured;
            }
            result_response(id, result)
        }
        Err(ToolError::InvalidArguments(reason)) => error_response(id, INVALID_PARAMS, &reason),
        Err(error) => result_response(
            id,
            json!({
                "content": [{ "type": "text", "text": error.to_string() }],
                "isError": true,
            }),
        ),
    }
}

/// A required string argument.
pub fn string_argument<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, ToolError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::InvalidArguments(format!("{name} must be a string")))
}

/// An optional non-negative integer argument.
pub fn integer_argument(arguments: &Value, name: &str) -> Result<Option<u64>, ToolError> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            ToolError::InvalidArguments(format!("{name} must be a non-negative integer"))
        }),
    }
}

/// Hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Parse `--<flag> <value>` as the only accepted arguments, so a caged
/// launch whose argv drifts from its policy fails in the tool as well.
pub fn single_flag_argument(arguments: &[String], flag: &str) -> Result<String, String> {
    match arguments {
        [name, value] if name == flag => Ok(value.clone()),
        _ => Err(format!("usage: {flag} <value>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl ToolServer for Echo {
        fn name(&self) -> &str {
            "echo"
        }
        fn version(&self) -> &str {
            "1"
        }
        fn tools(&self) -> Vec<ToolDescriptor> {
            vec![ToolDescriptor {
                name: "echo",
                description: "Return the message",
                input_schema: json!({ "type": "object", "properties": { "message": { "type": "string" } } }),
                read_only: true,
            }]
        }
        fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
            assert_eq!(name, "echo");
            let message = string_argument(arguments, "message")?;
            if message == "refuse" {
                return Err(ToolError::Refused("no".to_string()));
            }
            Ok(ToolOutput::text(message))
        }
    }

    fn run(input: &str) -> Vec<Value> {
        let mut output = Vec::new();
        serve(Echo, input.as_bytes(), &mut output).unwrap_or_else(|error| panic!("{error}"));
        String::from_utf8(output)
            .unwrap_or_else(|error| panic!("{error}"))
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}")))
            .collect()
    }

    #[test]
    fn the_handshake_listing_and_calls_follow_the_protocol() {
        let responses = run(concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"hi\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"refuse\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"missing\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"resources/list\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\"}\n",
        ));
        assert_eq!(responses.len(), 8);
        assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(responses[0]["result"]["serverInfo"]["name"], "echo");
        assert_eq!(responses[1]["result"]["tools"][0]["name"], "echo");
        assert_eq!(
            responses[1]["result"]["tools"][0]["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(responses[2]["result"]["content"][0]["text"], "hi");
        assert_eq!(responses[2]["result"]["isError"], false);
        assert_eq!(responses[3]["result"]["isError"], true);
        assert_eq!(responses[4]["error"]["code"], INVALID_PARAMS);
        assert_eq!(responses[5]["error"]["code"], INVALID_PARAMS);
        assert_eq!(responses[6]["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(responses[7]["result"], json!({}));
    }

    #[test]
    fn malformed_and_oversized_lines_are_reported_and_the_stream_continues() {
        let oversized = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"pad\":\"{}\"}}\n",
            "x".repeat(MAX_LINE_BYTES)
        );
        let input = format!(
            "not json\n{oversized}{{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}}\n\n"
        );
        let responses = run(&input);
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[1]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[2]["id"], 9);
    }

    #[test]
    fn a_single_flag_is_the_whole_argument_contract() {
        let root = ["--root".to_string(), "/srv".to_string()];
        assert_eq!(single_flag_argument(&root, "--root").as_deref(), Ok("/srv"));
        assert!(single_flag_argument(&root, "--artifact").is_err());
        assert!(single_flag_argument(&["--root".to_string()], "--root").is_err());
        assert!(single_flag_argument(
            &["--root".to_string(), "/a".to_string(), "x".to_string()],
            "--root"
        )
        .is_err());
    }
}
