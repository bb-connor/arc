//! `chio-tool-repo-reader --root <directory>`: read-only access to one
//! directory tree.
//!
//! Every path is relative to the root and resolves inside it; a path that
//! leaves the root through `..` or a symlink is refused before the kernel
//! ever sees it. A session may read at most 64 distinct files and 4 MiB in
//! total, and one read returns at most 256 KiB, so a caller cannot use the
//! tool to drain a repository.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use chio_reference_tools::{
    integer_argument, serve, single_flag_argument, string_argument, ToolDescriptor, ToolError,
    ToolOutput, ToolServer,
};
use serde_json::{json, Value};

const MAX_FILES_PER_SESSION: usize = 64;
const MAX_BYTES_PER_SESSION: u64 = 4 * 1024 * 1024;
const MAX_BYTES_PER_READ: u64 = 256 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;

struct RepoReader {
    root: PathBuf,
    files_read: BTreeSet<PathBuf>,
    bytes_read: u64,
}

impl RepoReader {
    fn open(root: &str) -> Result<Self, String> {
        let root = Path::new(root);
        if !root.is_absolute() {
            return Err("the root must be an absolute path".to_string());
        }
        let root = root
            .canonicalize()
            .map_err(|error| format!("root {}: {error}", root.display()))?;
        if !root.is_dir() {
            return Err(format!("root {} is not a directory", root.display()));
        }
        Ok(Self {
            root,
            files_read: BTreeSet::new(),
            bytes_read: 0,
        })
    }

    /// Resolve a caller path inside the root, following symlinks but
    /// refusing any resolution that ends outside it.
    fn resolve(&self, path: &str) -> Result<PathBuf, ToolError> {
        if path.is_empty() || path.len() > 4096 || path.contains('\0') {
            return Err(ToolError::InvalidArguments(
                "path must be a non-empty relative path".to_string(),
            ));
        }
        let relative = Path::new(path);
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err(ToolError::Refused(format!(
                "{path} is not a plain relative path inside the root"
            )));
        }
        let candidate = self.root.join(relative);
        let resolved = candidate
            .canonicalize()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ToolError::Failed(format!("{path} does not exist")),
                _ => ToolError::Failed(format!("{path}: {error}")),
            })?;
        if !resolved.starts_with(&self.root) {
            return Err(ToolError::Refused(format!(
                "{path} resolves outside the root"
            )));
        }
        Ok(resolved)
    }

    fn list_directory(&self, arguments: &Value) -> Result<ToolOutput, ToolError> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        let directory = self.resolve(path)?;
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| ToolError::Failed(format!("{path}: {error}")))?;
        let mut listing = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| ToolError::Failed(format!("{path}: {error}")))?;
            let metadata = entry
                .metadata()
                .map_err(|error| ToolError::Failed(format!("{path}: {error}")))?;
            let kind = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            listing.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "kind": kind,
                "size": metadata.len(),
            }));
            if listing.len() > MAX_DIRECTORY_ENTRIES {
                return Err(ToolError::Refused(format!(
                    "{path} holds more than {MAX_DIRECTORY_ENTRIES} entries"
                )));
            }
        }
        listing.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        Ok(ToolOutput::structured(
            json!({ "path": path, "entries": listing }),
        ))
    }

    fn read_file(&mut self, arguments: &Value) -> Result<ToolOutput, ToolError> {
        let path = string_argument(arguments, "path")?;
        let limit = integer_argument(arguments, "max_bytes")?
            .unwrap_or(MAX_BYTES_PER_READ)
            .min(MAX_BYTES_PER_READ);
        let resolved = self.resolve(path)?;
        if !resolved.is_file() {
            return Err(ToolError::Refused(format!("{path} is not a regular file")));
        }
        if !self.files_read.contains(&resolved) && self.files_read.len() >= MAX_FILES_PER_SESSION {
            return Err(ToolError::Refused(format!(
                "this session already read {MAX_FILES_PER_SESSION} distinct files"
            )));
        }
        let remaining = MAX_BYTES_PER_SESSION.saturating_sub(self.bytes_read);
        if remaining == 0 {
            return Err(ToolError::Refused(
                "this session's read budget is exhausted".to_string(),
            ));
        }
        let file = std::fs::File::open(&resolved)
            .map_err(|error| ToolError::Failed(format!("{path}: {error}")))?;
        let mut bytes = Vec::new();
        file.take(limit.min(remaining) + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ToolError::Failed(format!("{path}: {error}")))?;
        let truncated =
            u64::try_from(bytes.len()).map_or(true, |length| length > limit.min(remaining));
        if truncated {
            bytes.pop();
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| ToolError::Refused(format!("{path} is not UTF-8 text")))?;
        self.bytes_read = self.bytes_read.saturating_add(text.len() as u64);
        self.files_read.insert(resolved);
        Ok(ToolOutput::structured(json!({
            "path": path,
            "content": text,
            "truncated": truncated,
        })))
    }

    fn stat(&self, arguments: &Value) -> Result<ToolOutput, ToolError> {
        let path = string_argument(arguments, "path")?;
        let resolved = self.resolve(path)?;
        let metadata = std::fs::metadata(&resolved)
            .map_err(|error| ToolError::Failed(format!("{path}: {error}")))?;
        let kind = if metadata.is_dir() {
            "directory"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        Ok(ToolOutput::structured(json!({
            "path": path,
            "kind": kind,
            "size": metadata.len(),
        })))
    }
}

impl ToolServer for RepoReader {
    fn name(&self) -> &str {
        "chio-tool-repo-reader"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn tools(&self) -> Vec<ToolDescriptor> {
        vec![
            ToolDescriptor {
                name: "list_directory",
                description: "List the entries of a directory inside the root",
                input_schema: json!({
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                }),
                read_only: true,
            },
            ToolDescriptor {
                name: "read_file",
                description: "Read a UTF-8 file inside the root, at most 256 KiB per read",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "max_bytes": { "type": "integer", "minimum": 0 },
                    },
                    "required": ["path"],
                }),
                read_only: true,
            },
            ToolDescriptor {
                name: "stat",
                description: "Report the kind and size of a path inside the root",
                input_schema: json!({
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"],
                }),
                read_only: true,
            },
        ]
    }

    fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
        match name {
            "list_directory" => self.list_directory(arguments),
            "read_file" => self.read_file(arguments),
            "stat" => self.stat(arguments),
            _ => Err(ToolError::InvalidArguments(format!("unknown tool {name}"))),
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let root = match single_flag_argument(&arguments, "--root") {
        Ok(root) => root,
        Err(usage) => {
            eprintln!("chio-tool-repo-reader: {usage}");
            return ExitCode::FAILURE;
        }
    };
    let reader = match RepoReader::open(&root) {
        Ok(reader) => reader,
        Err(error) => {
            eprintln!("chio-tool-repo-reader: {error}");
            return ExitCode::FAILURE;
        }
    };
    match serve(reader, std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-tool-repo-reader: {error}");
            ExitCode::FAILURE
        }
    }
}
