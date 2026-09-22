//! One strict nonce operation survives process transport and abrupt host death.
mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

struct Server {
    effect: PathBuf,
    crash: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "tools"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["append".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let append = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.effect)?;
            writeln!(file, "external-effect")?;
            file.sync_all()
        };
        append().map_err(|error| KernelError::Internal(error.to_string()))?;
        if self.crash {
            std::process::exit(73);
        }
        Ok(arguments)
    }
}

fn kernel(directory: &Path, crash: bool) -> Result<std::sync::Arc<chio_kernel::ChioKernel>> {
    support::kernel_with_artifacts(
        directory,
        Box::new(Server {
            effect: directory.join("external.log"),
            crash,
        }),
        false,
        true,
        false,
    )
}

#[tokio::test]
async fn strict_nonce_call_completes_once_and_replays_after_reopening() -> Result {
    let directory = tempfile::tempdir()?;
    let (original_receipt, original_nonce) = {
        let kernel = kernel(directory.path(), false)?;
        let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
        support::root(&runtime, &kernel, 1)?;
        let request =
            runtime.tool_request("root", "publish", "tools", "append", json!({"value": 1}))?;
        let response = runtime.invoke("root", "publish", &request).await?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(
            response.output.is_some(),
            "strict preflight was returned as a completed call"
        );
        assert!(response.receipt.verify_signature()?);
        assert_eq!(
            std::fs::read_to_string(directory.path().join("external.log"))?,
            "external-effect\n"
        );
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        (
            response.receipt,
            response
                .execution_nonce
                .ok_or("missing original execution nonce")?,
        )
    };
    let kernel = kernel(directory.path(), false)?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    let request =
        runtime.tool_request("root", "publish", "tools", "append", json!({"value": 1}))?;
    for _ in 0..2 {
        let replay = runtime.invoke("root", "publish", &request).await?;
        assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
        assert_eq!(
            serde_json::to_value(replay.receipt)?,
            serde_json::to_value(&original_receipt)?
        );
        assert_eq!(
            replay.execution_nonce.as_deref(),
            Some(original_nonce.as_ref())
        );
    }
    assert_eq!(
        std::fs::read_to_string(directory.path().join("external.log"))?,
        "external-effect\n"
    );
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}

#[test]
fn strict_nonce_unknown_effect_keeps_original_custody_after_process_death() -> Result {
    let directory = tempfile::tempdir()?;
    let phase = |phase: &str| -> Result<std::process::ExitStatus> {
        Ok(Command::new(std::env::current_exe()?)
            .args(["--exact", "strict_nonce_subprocess", "--nocapture"])
            .env("CHIO_PROCESS_NONCE_TEST_DIRECTORY", directory.path())
            .env("CHIO_PROCESS_NONCE_TEST_PHASE", phase)
            .status()?)
    };
    assert_eq!(phase("crash")?.code(), Some(73));
    assert!(phase("recover")?.success());
    assert!(phase("recover")?.success());
    assert_eq!(
        std::fs::read_to_string(directory.path().join("external.log"))?,
        "external-effect\n"
    );
    Ok(())
}

#[tokio::test]
async fn strict_nonce_subprocess() -> Result {
    let Ok(directory) = std::env::var("CHIO_PROCESS_NONCE_TEST_DIRECTORY") else {
        return Ok(());
    };
    let directory = Path::new(&directory);
    let crash = std::env::var("CHIO_PROCESS_NONCE_TEST_PHASE")? == "crash";
    let kernel = kernel(directory, crash)?;
    let runtime = ProcessRuntime::open(directory.join("process.db"), kernel.clone())?;
    if crash {
        support::root(&runtime, &kernel, 1)?;
    }
    let request =
        runtime.tool_request("root", "publish", "tools", "append", json!({"value": 1}))?;
    let response = runtime.invoke("root", "publish", &request).await?;
    assert!(!crash, "strict preflight failed to reach the real tool");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("receipt metadata")?;
    assert_eq!(
        metadata["admission_operation"]["projected_state"],
        "outcome_unknown_after_dispatch"
    );
    assert!(metadata["admission_operation"]["retained_dispatch_commit"].is_object());
    let nonce = response
        .execution_nonce
        .ok_or("unknown effect lost original nonce")?;
    assert_eq!(nonce.nonce.bound_to.request_id, request.request_id);
    let retained = directory.join("recovered-nonce.json");
    if retained.exists() {
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(retained)?)?,
            serde_json::to_value(&nonce)?
        );
    } else {
        std::fs::write(retained, serde_json::to_vec(&nonce)?)?;
    }
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}
