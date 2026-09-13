//! `chio-tool-digest`: pure computation over the caller's input.
//!
//! The tool needs no file, network or environment grant at all, which makes
//! it the smallest possible launch under the cage and a control for the
//! other two tools: if this one cannot start, the host is the problem.

use std::process::ExitCode;

use chio_reference_tools::{
    serve, sha256_hex, string_argument, ToolDescriptor, ToolError, ToolOutput, ToolServer,
};
use serde_json::{json, Value};

const MAX_INPUT_BYTES: usize = 1024 * 1024;

struct Digest;

impl ToolServer for Digest {
    fn name(&self) -> &str {
        "chio-tool-digest"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn tools(&self) -> Vec<ToolDescriptor> {
        vec![
            ToolDescriptor {
                name: "sha256",
                description: "Hex SHA-256 of the UTF-8 bytes of a text",
                input_schema: json!({
                    "type": "object",
                    "properties": { "text": { "type": "string" } },
                    "required": ["text"],
                }),
                read_only: true,
            },
            ToolDescriptor {
                name: "canonical_json",
                description: "A JSON value with sorted keys and no whitespace, and its SHA-256",
                input_schema: json!({
                    "type": "object",
                    "properties": { "value": {} },
                    "required": ["value"],
                }),
                read_only: true,
            },
        ]
    }

    fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
        match name {
            "sha256" => {
                let text = string_argument(arguments, "text")?;
                if text.len() > MAX_INPUT_BYTES {
                    return Err(ToolError::Refused(format!(
                        "text exceeds {MAX_INPUT_BYTES} bytes"
                    )));
                }
                Ok(ToolOutput::structured(
                    json!({ "sha256": sha256_hex(text.as_bytes()) }),
                ))
            }
            "canonical_json" => {
                let value = arguments
                    .get("value")
                    .ok_or_else(|| ToolError::InvalidArguments("value is required".to_string()))?;
                let canonical = value.to_string();
                if canonical.len() > MAX_INPUT_BYTES {
                    return Err(ToolError::Refused(format!(
                        "value exceeds {MAX_INPUT_BYTES} bytes"
                    )));
                }
                Ok(ToolOutput::structured(json!({
                    "canonical": canonical,
                    "sha256": sha256_hex(canonical.as_bytes()),
                })))
            }
            _ => Err(ToolError::InvalidArguments(format!("unknown tool {name}"))),
        }
    }
}

fn main() -> ExitCode {
    if std::env::args().len() > 1 {
        eprintln!("chio-tool-digest: takes no arguments");
        return ExitCode::FAILURE;
    }
    match serve(Digest, std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-tool-digest: {error}");
            ExitCode::FAILURE
        }
    }
}
