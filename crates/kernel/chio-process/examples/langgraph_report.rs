#[cfg(unix)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(unix)]
#[tokio::main]
async fn main() -> support::Result {
    report::run().await
}

#[cfg(not(unix))]
fn main() {
    eprintln!("langgraph_report requires Unix sockets and the Python LangGraph process extra");
    std::process::exit(1);
}

#[cfg(unix)]
mod report {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use chio_core_types::crypto::Keypair;
    use chio_core_types::receipt::body::ChioReceipt;
    use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
    use chio_process::worker::{WorkerServer, WorkerService};
    use chio_process::ProcessRuntime;
    use serde_json::{json, Value};
    use tokio::io::AsyncWriteExt;

    use crate::support::{self, Result};

    struct ReportTools {
        directory: PathBuf,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for ReportTools {
        fn server_id(&self) -> &str {
            "tools"
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["read".into(), "append".into()]
        }
        async fn invoke(
            &self,
            tool: &str,
            args: Value,
            _: Option<&mut dyn NestedFlowBridge>,
        ) -> std::result::Result<Value, KernelError> {
            let result = (|| -> Result<Value> {
                match tool {
                    "read" => {
                        let sources: Value = serde_json::from_slice(&std::fs::read(
                            self.directory.join("sources.json"),
                        )?)?;
                        let source = args["source"].as_str().ok_or("missing source")?;
                        let content = sources
                            .get(source)
                            .and_then(Value::as_str)
                            .ok_or("unknown source")?;
                        Ok(json!({"source": source, "content": content}))
                    }
                    "append" => {
                        let report = args["report"].as_str().ok_or("missing report")?;
                        let mut file = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(self.directory.join("publications.jsonl"))?;
                        let mut bytes = serde_json::to_vec(&json!({"report": report}))?;
                        bytes.push(b'\n');
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        Ok(json!({"published": true}))
                    }
                    _ => Err("unknown tool".into()),
                }
            })();
            result.map_err(|_| KernelError::Internal("report fixture failed".into()))
        }
    }

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    async fn worker(config: &Value, expected_code: i32) -> Result<Value> {
        let python = std::env::var_os("CHIO_LANGGRAPH_PYTHON")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("sdks/python/chio-langgraph/.venv/bin/python"));
        let mut process = tokio::process::Command::new(python)
            .arg(repository().join("sdks/python/chio-langgraph/examples/recover_report.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = process.stdin.take().ok_or("missing worker stdin")?;
        stdin.write_all(&serde_json::to_vec(config)?).await?;
        drop(stdin);
        let output =
            tokio::time::timeout(Duration::from_secs(90), process.wait_with_output()).await??;
        if output.status.code() != Some(expected_code) {
            return Err(format!(
                "graph worker failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        if expected_code == 0 {
            Ok(serde_json::from_slice(&output.stdout)?)
        } else if expected_code == 1 {
            assert!(String::from_utf8_lossy(&output.stderr).contains("ChioProcessToolError"));
            Ok(Value::Null)
        } else {
            Ok(Value::Null)
        }
    }

    fn publications(directory: &Path) -> Result<Vec<Value>> {
        let path = directory.join("publications.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        std::fs::read_to_string(path)?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }

    pub async fn run() -> Result {
        let temporary = tempfile::tempdir()?;
        let sources = json!({
            "runtime": std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))?,
            "worker": std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("WORKER_PROTOCOL.md"))?,
        });
        let mut measurements = Vec::new();
        let mut baseline_publication = None;
        let mut versions = Value::Null;
        for backend in ["baseline", "chio", "denied"] {
            let directory = temporary.path().join(backend);
            support::private_dir(&directory)?;
            std::fs::write(
                directory.join("sources.json"),
                serde_json::to_vec(&sources)?,
            )?;
            let mut config = json!({"backend": backend, "phase": "first", "directory": directory});
            let mut host = None;
            if backend != "baseline" {
                let kernel = support::kernel(
                    &directory,
                    Box::new(ReportTools {
                        directory: directory.clone(),
                    }),
                )?;
                let runtime = ProcessRuntime::open(directory.join("process.db"), kernel.clone())?;
                let root = support::root(&runtime, &kernel, 3)?;
                let grants: &[&str] = if backend == "denied" {
                    &["read"]
                } else {
                    &["read", "append"]
                };
                let capability = support::child(
                    &root,
                    &support::parent_key(),
                    "graph",
                    &Keypair::generate(),
                    support::scope(grants),
                )?;
                runtime.spawn("root", "graph", &capability)?;
                let service = WorkerService::new(runtime.clone());
                let credential = service.issue_credential("graph", capability.expires_at)?;
                let socket = directory.join("worker.sock");
                let listener = WorkerServer::bind(&socket, service)?;
                config["socket_path"] = json!(socket);
                config["credential"] = json!(credential.expose_secret());
                let (stop, stopped) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(listener.serve(async {
                    let _ = stopped.await;
                }));
                host = Some((runtime, stop, task));
            }
            let started = Instant::now();
            if backend == "denied" {
                worker(&config, 1).await?;
                assert!(publications(&directory)?.is_empty());
                measurements.push(json!({"backend": backend, "completed": false, "publications": 0, "worker_elapsed_ms": started.elapsed().as_millis()}));
            } else {
                worker(&config, 76).await?;
                assert_eq!(publications(&directory)?.len(), 1);
                config["phase"] = json!("resume");
                let resumed = worker(&config, 0).await?;
                assert_eq!(resumed["complete"], true);
                let publications = publications(&directory)?;
                let expected = if backend == "baseline" { 2 } else { 1 };
                assert_eq!(publications.len(), expected);
                if backend == "baseline" {
                    versions = resumed["versions"].clone();
                    assert_eq!(publications[0], publications[1]);
                    baseline_publication = Some(publications[0].clone());
                } else {
                    assert_eq!(resumed["versions"], versions);
                    assert_eq!(Some(&publications[0]), baseline_publication.as_ref());
                    let original: Value = serde_json::from_slice(&std::fs::read(
                        directory.join("first-publication.json"),
                    )?)?;
                    let original_receipt =
                        &original["messages"][0]["artifact"]["chio"]["receipt_json"];
                    let messages = resumed["tool_results"]
                        .as_array()
                        .ok_or("missing tool results")?;
                    for message in messages {
                        let receipt: ChioReceipt = serde_json::from_str(
                            message["artifact"]["chio"]["receipt_json"]
                                .as_str()
                                .ok_or("missing receipt")?,
                        )?;
                        assert!(receipt.verify_signature()?);
                        assert_eq!(receipt.kernel_key, support::issuer().public_key());
                    }
                    assert_eq!(
                        &messages[2]["artifact"]["chio"]["receipt_json"],
                        original_receipt
                    );
                }
                measurements.push(json!({"backend": backend, "completed": true, "publications": publications.len(),
                    "duplicate_publications": publications.len() - 1, "worker_elapsed_ms": started.elapsed().as_millis()}));
            }
            if let Some((runtime, stop, task)) = host {
                assert_eq!(runtime.process("root")?.tree_calls, 3);
                stop.send(()).map_err(|_| "server stopped early")?;
                task.await??;
            }
        }
        let output_dir = std::env::var_os("CHIO_GRAPH_REPORT_OUTPUT")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/langgraph-report"));
        std::fs::create_dir_all(&output_dir)?;
        let publication = baseline_publication.ok_or("no report produced")?;
        std::fs::write(
            output_dir.join("report.md"),
            publication["report"].as_str().ok_or("invalid report")?,
        )?;
        let evidence = json!({"scenario": "worker death after publication return, before graph checkpoint",
            "planning": "deterministic trace; no LLM", "checkpointer": "LangGraph SqliteSaver, synchronous durability",
            "versions": versions, "measurements": measurements});
        std::fs::write(
            output_dir.join("comparison.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        println!("Report and evidence: {}", output_dir.display());
        Ok(())
    }
}
