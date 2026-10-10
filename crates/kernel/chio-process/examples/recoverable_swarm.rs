//! Local crash/restart laboratory. Uses fixed test keys in a disposable private
//! directory, no model provider, network listener, or external credentials.

#[path = "../tests/support/mod.rs"]
mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use chio_core_types::crypto::Keypair;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

struct ArtifactWriter(PathBuf);

#[async_trait::async_trait]
impl ToolServerConnection for ArtifactWriter {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.0)?;
            file.write_all(format!("{}\n", args["worker"]).as_bytes())?;
            file.sync_all()
        };
        write().map_err(|e| KernelError::Internal(e.to_string()))?;
        Ok(json!({"published": args["worker"]}))
    }
}

async fn worker(path: &Path, phase: &str) -> Result {
    let kernel = support::kernel(path, Box::new(ArtifactWriter(path.join("effects.log"))))?;
    let runtime = ProcessRuntime::open(path.join("process.db"), kernel.clone())?;
    if phase == "first" {
        let parent = support::root(&runtime, &kernel, 8)?;
        for index in 0..8 {
            let id = format!("worker-{index}");
            let cap = support::child(
                &parent,
                &support::parent_key(),
                &id,
                &Keypair::generate(),
                support::scope(&["append"]),
            )?;
            runtime.spawn("root", &id, &cap)?;
        }
    }
    let count = if phase == "first" { 4 } else { 8 };
    let mut tasks = Vec::new();
    for index in 0..count {
        let process = runtime.clone();
        tasks.push(tokio::spawn(async move {
            let id = format!("worker-{index}");
            let request = process.tool_request(
                &id,
                "publish",
                "tools",
                "append",
                json!({"worker": index}),
            )?;
            let response = process.invoke(&id, "publish", &request).await?;
            if response.verdict != Verdict::Allow || !response.receipt.verify_signature()? {
                return Err(chio_process::ProcessError::Invalid(
                    "worker did not receive a signed allow receipt",
                ));
            }
            Ok::<_, chio_process::ProcessError>((index, response.receipt))
        }));
    }
    for task in tasks {
        let (index, receipt) = task.await??;
        let receipt_path = path.join(format!("receipt-{index}.json"));
        let value = serde_json::to_value(&receipt)?;
        if phase == "second" && index < 4 {
            let original: Value = serde_json::from_slice(&std::fs::read(&receipt_path)?)?;
            if value != original {
                return Err("recovery changed the original receipt".into());
            }
        } else {
            std::fs::write(&receipt_path, serde_json::to_vec(&value)?)?;
        }
    }
    if phase == "first" {
        println!(
            "Four workers committed their effects. Exiting before the coordinator checkpoint."
        );
        std::process::exit(75);
    }
    runtime.checkpoint("root", 0, json!({"completed_workers": 8}))?;
    if runtime.process("root")?.tree_calls != 8 {
        return Err("shared call ceiling changed during replay".into());
    }
    println!("Fresh process: four original receipts replayed, four remaining workers completed.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 4 && args[1] == "--worker" {
        return worker(
            Path::new(&args[2]),
            args[3].to_str().ok_or("invalid phase")?,
        )
        .await;
    }
    let dir = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    println!(
        "Starting eight capability-bound logical workers with a shared ceiling of eight calls."
    );
    let first = Command::new(&executable)
        .arg("--worker")
        .arg(dir.path())
        .arg("first")
        .status()?;
    if first.code() != Some(75) {
        return Err("first process did not reach the crash boundary".into());
    }
    let second = Command::new(&executable)
        .arg("--worker")
        .arg(dir.path())
        .arg("second")
        .status()?;
    if !second.success() {
        return Err("fresh process failed to recover".into());
    }
    let effects = std::fs::read_to_string(dir.path().join("effects.log"))?;
    let mut workers: Vec<_> = effects.lines().collect();
    workers.sort_unstable();
    if workers != ["0", "1", "2", "3", "4", "5", "6", "7"] {
        return Err("external effects are missing or duplicated".into());
    }
    println!(
        "Verified: 12 invocation attempts, exactly 8 external effects, 8 signed worker receipts."
    );
    println!("Checkpoint recovered. No model keys or external services were needed.");
    Ok(())
}
