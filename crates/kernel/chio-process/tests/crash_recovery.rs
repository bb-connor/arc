mod support;

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

/// `append` is a side effect; `read` is declared free of side effects and
/// records each execution in a separate log only so the test can count them.
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
        vec!["append".into(), "read".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool == "read"
    }
    async fn invoke(
        &self,
        tool: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let (path, line) = if tool == "read" {
            (self.path.with_file_name("reads.log"), "read-executed")
        } else {
            (self.path.clone(), "external-effect")
        };
        let append = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)?;
            writeln!(file, "{line}")?;
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

#[test]
fn unknown_read_only_outcome_is_redispatched_under_a_fresh_request_identity() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-in-read")?.code(), Some(73));
    assert!(phase(dir.path(), "recover-read")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\nread-executed\n"
    );
    assert!(!dir.path().join("external.log").exists());
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
            crash_after_effect: phase == "crash-in-tool" || phase == "crash-in-read",
        }),
    )?;
    let runtime = ProcessRuntime::open(dir.join("process.db"), kernel.clone())?;
    if phase == "crash-in-tool" || phase == "complete-then-exit" || phase == "crash-in-read" {
        support::root(&runtime, &kernel, 1)?;
    }
    if phase == "crash-in-read" || phase == "recover-read" {
        let request = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        let first = runtime.request_id("root", "peek")?;
        if phase == "crash-in-read" {
            assert_eq!(request.request_id, first);
            let _ = runtime.invoke("root", "peek", &request).await;
            unreachable!("the read-only tool exits the process before returning");
        }
        // Recovery reports the first dispatch unknown; a read-only tool earns a
        // fresh dispatch under the next attempt's identity, still one logical call.
        assert_eq!(request.request_id, first);
        let response = runtime.invoke("root", "peek", &request).await?;
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "{:?} {:?}",
            response.reason,
            response.receipt.metadata
        );
        assert_ne!(response.request_id, first);
        assert!(response.receipt.verify_signature()?);
        let again = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        assert_eq!(again.request_id, response.request_id);
        let replay = runtime.invoke("root", "peek", &again).await?;
        assert_eq!(replay.request_id, response.request_id);
        assert_eq!(
            serde_json::to_value(&replay.receipt)?,
            serde_json::to_value(&response.receipt)?
        );
        assert!(matches!(
            runtime.invoke("root", "peek", &request).await,
            Err(chio_process::ProcessError::Invalid(_))
        ));
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        return Ok(());
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
