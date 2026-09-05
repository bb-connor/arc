//! Disposable qualification fixture. Fixed test signing keys come from support.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::ChioReceipt;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::worker::{WorkerServer, WorkerService, PROTOCOL};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::support::{self, Result};

pub const PHASE: &str = "CHIO_POLYGLOT_PHASE";
pub const DIRECTORY: &str = "CHIO_POLYGLOT_DIRECTORY";

struct InventoryTools {
    directory: PathBuf,
}

#[async_trait::async_trait]
impl ToolServerConnection for InventoryTools {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read".into(), "append".into()]
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        // The pinned read snapshot and append target are selected by the host.
        // Workers supply no paths, commands or arbitrary filesystem access.
        let result = (|| -> Result<Value> {
            match tool {
                "read" => Ok(serde_json::from_slice(&std::fs::read(
                    self.directory.join("source.json"),
                )?)?),
                "append" => {
                    let mut log = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(self.directory.join("inventory.jsonl"))?;
                    let mut bytes = serde_json::to_vec(&arguments)?;
                    bytes.push(b'\n');
                    log.write_all(&bytes)?;
                    log.sync_all()?;
                    Ok(arguments)
                }
                _ => Err("unknown fixture tool".into()),
            }
        })();
        result.map_err(|_| KernelError::Internal("inventory fixture failed".into()))
    }
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

async fn worker(language: &str, socket: &Path, secret: &str) -> Result<Value> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/workers");
    let mut command = if language == "python" {
        let mut command = tokio::process::Command::new("python3");
        command.arg(script.join("inventory.py"));
        command.env(
            "PYTHONPATH",
            repository().join("sdks/python/chio-process/src"),
        );
        command
    } else {
        let mut command = tokio::process::Command::new("node");
        command.arg(script.join("inventory.mjs"));
        command
    };
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("worker stdin unavailable")?;
    stdin
        .write_all(&serde_json::to_vec(
            &json!({"socket_path": socket, "credential": secret}),
        )?)
        .await?;
    drop(stdin);
    let output = tokio::time::timeout(std::time::Duration::from_secs(90), child.wait_with_output())
        .await??;
    if !output.status.success() {
        return Err(format!(
            "{language} worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub async fn run_phase(directory: &Path, first: bool) -> Result {
    let kernel = support::kernel(
        directory,
        Box::new(InventoryTools {
            directory: directory.to_owned(),
        }),
    )?;
    let runtime = ProcessRuntime::open(directory.join("process.db"), kernel.clone())?;
    let service = WorkerService::new(runtime.clone());
    let secrets = if first {
        let parent = support::root(&runtime, &kernel, 4)?;
        let mut secrets = serde_json::Map::new();
        for language in ["python", "javascript"] {
            let cap = support::child(
                &parent,
                &support::parent_key(),
                language,
                &Keypair::generate(),
                support::scope(&["read", "append"]),
            )?;
            runtime.spawn("root", language, &cap)?;
            secrets.insert(
                language.into(),
                json!(service
                    .issue_credential(language, cap.expires_at)?
                    .expose_secret()),
            );
        }
        // Private disposable host directory. These secrets are never printed.
        std::fs::write(
            directory.join("credentials.json"),
            serde_json::to_vec(&secrets)?,
        )?;
        Value::Object(secrets)
    } else {
        serde_json::from_slice(&std::fs::read(directory.join("credentials.json"))?)?
    };
    // A fresh socket per host start avoids unlinking an entry after a crash.
    let socket = directory.join(if first { "first.sock" } else { "resumed.sock" });
    let listener = WorkerServer::bind(&socket, service.clone())?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(listener.serve(async {
        let _ = stopped.await;
    }));
    let (python, javascript) = tokio::join!(
        worker(
            "python",
            &socket,
            secrets["python"]
                .as_str()
                .ok_or("missing python credential")?
        ),
        worker(
            "javascript",
            &socket,
            secrets["javascript"]
                .as_str()
                .ok_or("missing javascript credential")?
        )
    );
    let responses = json!({"python": python?, "javascript": javascript?});
    for language in ["python", "javascript"] {
        for operation in ["read", "published"] {
            let response = &responses[language][operation];
            assert_eq!(response["verdict"], "allow", "{response}");
            let receipt: ChioReceipt =
                serde_json::from_str(response["receipt_json"].as_str().ok_or("missing receipt")?)?;
            assert!(receipt.verify_signature()?);
            assert_eq!(response["terminal_state"]["state"], "completed");
        }
        assert_eq!(
            responses[language]["snapshot"]["checkpoint"]["revision"],
            "1"
        );
    }
    assert_eq!(
        responses["python"]["published"]["output"]["value"]["nonempty_lines"],
        responses["javascript"]["published"]["output"]["value"]["nonempty_lines"]
    );
    assert_eq!(runtime.process("root")?.tree_calls, 4);
    assert_eq!(
        std::fs::read_to_string(directory.join("inventory.jsonl"))?
            .lines()
            .count(),
        2
    );
    if first {
        std::fs::write(
            directory.join("original.json"),
            serde_json::to_vec(&responses)?,
        )?;
        // Exit without graceful server, kernel or SQLite teardown. The next
        // host process must authenticate the same secrets and replay receipts.
        std::process::exit(75);
    }
    let original: Value = serde_json::from_slice(&std::fs::read(directory.join("original.json"))?)?;
    for language in ["python", "javascript"] {
        assert_eq!(responses[language]["read"], original[language]["read"]);
        assert_eq!(
            responses[language]["published"],
            original[language]["published"]
        );
        let over_limit = json!({"protocol": PROTOCOL, "credential": secrets[language],
            "operation": {"op": "invoke", "operation_key": "new-effect", "server_id": "tools", "tool_name": "append", "arguments": {}}});
        let denied: Value = serde_json::from_slice(
            &service
                .handle_frame(over_limit.to_string().as_bytes())
                .await,
        )?;
        assert_eq!(denied["error"]["code"], "limit_reached");
    }
    stop.send(()).map_err(|_| "server already stopped")?;
    task.await??;
    println!("Python and JavaScript: 8 call attempts, 4 logical kernel calls, 2 publications, 4 original signed receipts; host crash recovered; shared ceiling enforced.");
    Ok(())
}

/// Launch two fresh host processes; each launches independent Python and Node
/// workers. Requires both interpreters. Absence is a failure, never a skip.
pub fn run_demo(executable: &Path, test_binary: bool) -> Result {
    let directory = tempfile::tempdir()?;
    support::private_dir(directory.path())?;
    let files = ["src/lib.rs", "src/worker.rs"].into_iter().map(|path| {
        Ok(json!({"path": path, "content": std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))?}))
    }).collect::<Result<Vec<Value>>>()?;
    std::fs::write(
        directory.path().join("source.json"),
        serde_json::to_vec(&json!({"files": files}))?,
    )?;
    for phase in ["first", "resume"] {
        let mut command = std::process::Command::new(executable);
        if test_binary {
            command.args(["--exact", "polyglot_host_phase", "--nocapture"]);
        }
        let output = command
            .env(PHASE, phase)
            .env(DIRECTORY, directory.path())
            .output()?;
        let expected = if phase == "first" { 75 } else { 0 };
        if output.status.code() != Some(expected) {
            return Err(format!(
                "host {phase} failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        if phase == "resume" {
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
    Ok(())
}
