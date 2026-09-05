mod support;

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

struct AppendServer {
    path: PathBuf,
    crash_after_effect: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for AppendServer {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let append = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.path)?;
            writeln!(file, "external-effect")?;
            file.sync_all()
        };
        append().map_err(|e| KernelError::Internal(e.to_string()))?;
        if self.crash_after_effect {
            // The real OS process exits after the external effect, before the
            // tool returns or any Rust destructor can reconcile the operation.
            std::process::exit(73);
        }
        Ok(json!({"published": true}))
    }
}

fn phase(dir: &std::path::Path, phase: &str) -> Result<std::process::ExitStatus> {
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", "subprocess_worker", "--nocapture"])
        .env("CHIO_PROCESS_TEST_DIRECTORY", dir)
        .env("CHIO_PROCESS_TEST_PHASE", phase)
        .status()?)
}

#[test]
fn completed_effect_survives_abrupt_exit_and_a_fresh_os_process() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "complete-then-exit")?.code(), Some(74));
    assert!(phase(dir.path(), "recover-complete")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("external.log"))?,
        "external-effect\n"
    );
    Ok(())
}

#[test]
fn unknown_effect_is_not_redispatched_after_process_death() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-in-tool")?.code(), Some(73));
    assert!(phase(dir.path(), "recover-unknown")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("external.log"))?,
        "external-effect\n"
    );
    Ok(())
}

#[tokio::test]
async fn subprocess_worker() -> Result {
    let Some(dir) = std::env::var_os("CHIO_PROCESS_TEST_DIRECTORY") else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    let phase = std::env::var("CHIO_PROCESS_TEST_PHASE")?;
    let kernel = support::kernel(
        &dir,
        Box::new(AppendServer {
            path: dir.join("external.log"),
            crash_after_effect: phase == "crash-in-tool",
        }),
    )?;
    let runtime = ProcessRuntime::open(dir.join("process.db"), kernel.clone())?;
    if phase == "crash-in-tool" || phase == "complete-then-exit" {
        support::root(&runtime, &kernel, 1)?;
    }
    let request = runtime.tool_request(
        "root",
        "publish",
        "tools",
        "append",
        json!({"report": "v1"}),
    )?;
    let response = runtime.invoke("root", "publish", &request).await?;
    if phase == "recover-unknown" {
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert!(response.output.is_none());
        assert!(response.receipt.verify_signature()?);
        assert!(
            response
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("OutcomeUnknownAfterDispatch"),
            "{:?}",
            response.reason
        );
    } else {
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let receipt = serde_json::to_value(&response.receipt)?;
        if phase == "complete-then-exit" {
            let mut file = std::fs::File::create(dir.join("original-receipt.json"))?;
            file.write_all(&serde_json::to_vec(&receipt)?)?;
            file.sync_all()?;
            std::process::exit(74);
        }
        let original: Value =
            serde_json::from_slice(&std::fs::read(dir.join("original-receipt.json"))?)?;
        assert_eq!(receipt, original);
    }
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}
