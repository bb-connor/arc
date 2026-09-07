//! `chio-tool-artifact-writer --artifact <file>`: write one pre-created file.
//!
//! The artifact exists before the tool starts and is the only path the
//! launch policy lets the tool write. The tool replaces its content in
//! place, never creating, renaming or removing anything, so the exact-file
//! grant the cage holds is the whole write surface.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chio_reference_tools::{
    serve, sha256_hex, single_flag_argument, string_argument, ToolDescriptor, ToolError,
    ToolOutput, ToolServer,
};
use serde_json::{json, Value};

const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;

struct ArtifactWriter {
    configured: String,
    artifact: PathBuf,
}

impl ArtifactWriter {
    fn open(artifact: &str) -> Result<Self, String> {
        let path = Path::new(artifact);
        if !path.is_absolute() {
            return Err("the artifact must be an absolute path".to_string());
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("artifact {}: {error}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!(
                "artifact {} must be a pre-created regular file",
                path.display()
            ));
        }
        Ok(Self {
            configured: artifact.to_string(),
            artifact: path.to_path_buf(),
        })
    }

    fn content(&self) -> Result<Vec<u8>, ToolError> {
        let file = std::fs::File::open(&self.artifact)
            .map_err(|error| ToolError::Failed(format!("artifact: {error}")))?;
        let mut bytes = Vec::new();
        file.take(MAX_ARTIFACT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ToolError::Failed(format!("artifact: {error}")))?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(ToolError::Refused(
                "the artifact is larger than the tool's ceiling".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn write_artifact(&self, arguments: &Value) -> Result<ToolOutput, ToolError> {
        let content = string_argument(arguments, "content")?;
        if content.len() > MAX_ARTIFACT_BYTES {
            return Err(ToolError::Refused(format!(
                "content exceeds {MAX_ARTIFACT_BYTES} bytes"
            )));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.artifact)
            .map_err(|error| ToolError::Failed(format!("artifact: {error}")))?;
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| ToolError::Failed(format!("artifact: {error}")))?;
        Ok(ToolOutput::structured(json!({
            "path": self.configured,
            "bytes_written": content.len(),
            "sha256": sha256_hex(content.as_bytes()),
        })))
    }

    fn read_artifact(&self) -> Result<ToolOutput, ToolError> {
        let bytes = self.content()?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ToolError::Refused("the artifact is not UTF-8 text".to_string()))?;
        Ok(ToolOutput::structured(
            json!({ "path": self.configured, "content": text }),
        ))
    }

    fn artifact_status(&self) -> Result<ToolOutput, ToolError> {
        let bytes = self.content()?;
        Ok(ToolOutput::structured(json!({
            "path": self.configured,
            "size": bytes.len(),
            "sha256": sha256_hex(&bytes),
        })))
    }
}

impl ToolServer for ArtifactWriter {
    fn name(&self) -> &str {
        "chio-tool-artifact-writer"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn tools(&self) -> Vec<ToolDescriptor> {
        vec![
            ToolDescriptor {
                name: "write_artifact",
                description: "Replace the artifact's content, at most 1 MiB",
                input_schema: json!({
                    "type": "object",
                    "properties": { "content": { "type": "string" } },
                    "required": ["content"],
                }),
                read_only: false,
            },
            ToolDescriptor {
                name: "read_artifact",
                description: "Read the artifact as UTF-8 text",
                input_schema: json!({ "type": "object", "properties": {} }),
                read_only: true,
            },
            ToolDescriptor {
                name: "artifact_status",
                description: "Report the artifact's size and SHA-256",
                input_schema: json!({ "type": "object", "properties": {} }),
                read_only: true,
            },
        ]
    }

    fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
        match name {
            "write_artifact" => self.write_artifact(arguments),
            "read_artifact" => self.read_artifact(),
            "artifact_status" => self.artifact_status(),
            _ => Err(ToolError::InvalidArguments(format!("unknown tool {name}"))),
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let artifact = match single_flag_argument(&arguments, "--artifact") {
        Ok(artifact) => artifact,
        Err(usage) => {
            eprintln!("chio-tool-artifact-writer: {usage}");
            return ExitCode::FAILURE;
        }
    };
    let writer = match ArtifactWriter::open(&artifact) {
        Ok(writer) => writer,
        Err(error) => {
            eprintln!("chio-tool-artifact-writer: {error}");
            return ExitCode::FAILURE;
        }
    };
    match serve(writer, std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-tool-artifact-writer: {error}");
            ExitCode::FAILURE
        }
    }
}
