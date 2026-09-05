use chio_kernel::{KernelError, ToolServerConnection};
use rustix::fs::{openat, Dir, Mode, OFlags};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command, sync::watch};

const MAX_FILE: u64 = 128 * 1024;
const MAX_ENTRIES: usize = 500;

pub(crate) struct WorkspaceTools {
    root: Arc<File>,
    workspace: PathBuf,
    check_command: Vec<String>,
    stop: watch::Sender<bool>,
}

impl WorkspaceTools {
    pub fn new(
        workspace: &Path,
        check_command: Vec<String>,
        stop: watch::Sender<bool>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            root: Arc::new(File::open(workspace)?),
            workspace: workspace.into(),
            check_command,
            stop,
        })
    }

    fn open(&self, path: &str, directory: bool, write: bool) -> std::io::Result<File> {
        if directory && path == "." {
            return self.root.try_clone();
        }
        let components: Vec<_> = Path::new(path).components().collect();
        if components.is_empty() || components.len() > 32 {
            return Err(invalid("invalid path"));
        }
        let mut parent = self.root.try_clone()?;
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(invalid("paths must stay inside the workspace"));
            };
            let name = name.to_str().ok_or_else(|| invalid("path must be UTF-8"))?;
            if name.starts_with('.')
                || name.ends_with(".pem")
                || name.ends_with(".key")
                || matches!(name, "node_modules" | "target" | "id_rsa" | "id_ed25519")
            {
                return Err(invalid("path is excluded from workspace tools"));
            }
            let is_directory = directory || index + 1 < components.len();
            let flags = OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | if is_directory {
                    OFlags::RDONLY | OFlags::DIRECTORY
                } else if write {
                    OFlags::RDWR
                } else {
                    OFlags::RDONLY
                };
            parent = File::from(openat(&parent, name, flags, Mode::empty())?);
        }
        let meta = parent.metadata()?;
        if !directory && (!meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_FILE) {
            return Err(invalid(
                "only regular, singly linked files up to 128 KiB are supported",
            ));
        }
        Ok(parent)
    }

    fn file_tool(&self, name: &str, args: &Value) -> std::io::Result<Value> {
        let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
        if name == "list_files" {
            let directory = self.open(path, true, false)?;
            let mut entries = vec![];
            for entry in Dir::read_from(&directory)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || matches!(name.as_str(), "target" | "node_modules") {
                    continue;
                }
                if entries.len() >= MAX_ENTRIES {
                    return Err(invalid(
                        "directory exceeds 500 entries; choose a more specific path",
                    ));
                }
                entries.push(name);
            }
            entries.sort();
            return Ok(json!({"path":path,"entries":entries}));
        }
        let mut file = self.open(path, false, name == "replace_text")?;
        let mut text = String::new();
        (&mut file).take(MAX_FILE + 1).read_to_string(&mut text)?;
        if text.len() as u64 > MAX_FILE {
            return Err(invalid("file exceeds 128 KiB"));
        }
        if name == "read_file" {
            return Ok(json!({"path":path,"text":text}));
        }
        if name != "replace_text" {
            return Err(invalid("unknown tool"));
        }
        let old = args
            .get("old_text")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("old_text is required"))?;
        let new = args
            .get("new_text")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("new_text is required"))?;
        if old.is_empty() || text.matches(old).count() != 1 {
            return Err(invalid(
                "old_text must match exactly once; read the file again",
            ));
        }
        let replacement = text.replacen(old, new, 1);
        if replacement.len() as u64 > MAX_FILE {
            return Err(invalid("replacement exceeds 128 KiB"));
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(replacement.as_bytes())?;
        file.set_len(replacement.len() as u64)?;
        file.sync_all()?;
        Ok(
            json!({"path":path,"before_sha256":chio_core::crypto::sha256_hex(text.as_bytes()),
            "after_sha256":chio_core::crypto::sha256_hex(replacement.as_bytes())}),
        )
    }

    async fn checks(&self) -> std::io::Result<Value> {
        let (program, arguments) = self
            .check_command
            .split_first()
            .ok_or_else(|| invalid("no check command configured"))?;
        let mut command = Command::new(program);
        command
            .args(arguments)
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn()?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("check stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("check stderr unavailable"))?;
        let mut stopped = self.stop.subscribe();
        let execution = async {
            let (status, stdout, stderr) =
                tokio::try_join!(child.wait(), read_output(stdout), read_output(stderr))?;
            Ok::<_, std::io::Error>(
                json!({"exit_code":status.code(),"passed":status.success(),"stdout":stdout,"stderr":stderr}),
            )
        };
        let result = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(60), execution) => result.unwrap_or_else(|_| Err(invalid("checks timed out after 60 seconds"))),
            _ = stopped.wait_for(|value| *value) => Err(invalid("checks stopped by operator")),
        };
        // Reap descendants even if the direct child exited while one held a pipe.
        if let Some(group) = group {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result
    }
}

async fn read_output(reader: impl tokio::io::AsyncRead + Unpin) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    reader.take(MAX_FILE + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(invalid("check output exceeded 128 KiB"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::other(message)
}

#[async_trait::async_trait]
impl ToolServerConnection for WorkspaceTools {
    fn server_id(&self) -> &str {
        "workspace"
    }
    fn tool_names(&self) -> Vec<String> {
        crate::Role::Editor
            .tools()
            .iter()
            .map(|name| (*name).into())
            .collect()
    }
    fn tool_is_read_only(&self, name: &str) -> bool {
        matches!(name, "read_file" | "list_files")
    }
    async fn invoke(
        &self,
        name: &str,
        arguments: Value,
        _bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        if *self.stop.borrow() {
            return Ok(json!({"is_error":true,"error":"task stopped"}));
        }
        let result = if name == "run_checks" {
            self.checks().await
        } else {
            self.file_tool(name, &arguments)
        };
        // A tool error is still an executed, receipted outcome. It must not be
        // confused with a successful edit or a passing check by the harness.
        Ok(result.unwrap_or_else(|error| json!({"is_error":true,"error":error.to_string()})))
    }
}

pub(crate) fn definitions(names: &[&str]) -> Vec<Value> {
    names.iter().map(|name| {
        let (description, properties, required) = match *name {
            "list_files" => ("List a workspace directory. Use path '.' for the root; hidden and build directories are excluded.", json!({"path":{"type":"string"}}), json!([])),
            "read_file" => ("Read one UTF-8 workspace file, up to 128 KiB. Use relative paths returned by list_files.", json!({"path":{"type":"string"}}), json!(["path"])),
            "replace_text" => ("Replace exactly one occurrence of old_text in an existing file. Read the file first. Ambiguous or missing matches reject without changing the file.", json!({"path":{"type":"string"},"old_text":{"type":"string"},"new_text":{"type":"string"}}), json!(["path","old_text","new_text"])),
            _ => ("Run the operator-configured project checks. No command arguments are accepted. Returns exit_code, passed, stdout and stderr; passed=false means checks failed.", json!({}), json!([])),
        };
        json!({"name":name,"description":description,"input_schema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_paths_and_ambiguous_edits_without_mutating_files() -> crate::Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("workspace");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("file.txt"), "same same")?;
        std::fs::write(root.join(".env"), "private")?;
        std::fs::write(temporary.path().join("outside.txt"), "outside")?;
        std::os::unix::fs::symlink(temporary.path().join("outside.txt"), root.join("link.txt"))?;
        std::os::unix::fs::symlink(temporary.path(), root.join("linked-directory"))?;
        std::fs::hard_link(temporary.path().join("outside.txt"), root.join("hard.txt"))?;
        let (stop, _) = watch::channel(false);
        let tools = WorkspaceTools::new(&root, vec![], stop)?;
        for path in [
            "../outside.txt",
            "/etc/passwd",
            ".env",
            "link.txt",
            "linked-directory/outside.txt",
            "hard.txt",
        ] {
            let result = tools
                .invoke("read_file", json!({"path":path}), None)
                .await?;
            assert_eq!(result["is_error"], true, "{path}: {result}");
        }
        for old in ["", "same", "absent"] {
            let result = tools
                .invoke(
                    "replace_text",
                    json!({"path":"file.txt","old_text":old,"new_text":"changed"}),
                    None,
                )
                .await?;
            assert_eq!(result["is_error"], true);
        }
        assert_eq!(std::fs::read_to_string(root.join("file.txt"))?, "same same");
        assert_eq!(
            std::fs::read_to_string(temporary.path().join("outside.txt"))?,
            "outside"
        );
        Ok(())
    }
}
