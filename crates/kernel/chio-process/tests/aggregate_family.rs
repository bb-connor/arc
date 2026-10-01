#![cfg(all(feature = "worker-server", unix))]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core_types::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::worker::{WorkerService, PROTOCOL};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

struct Tool(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for Tool {
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
        self.0.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        Ok(arguments)
    }
}

#[tokio::test]
async fn authenticated_siblings_share_issued_budget_across_contention_and_restart() -> Result {
    let directory = tempfile::tempdir()?;
    let effects = Arc::new(AtomicUsize::new(0));
    let kernel = support::kernel(directory.path(), Box::new(Tool(effects.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    let root = kernel.issue_aggregate_family_root(
        &support::parent_key().public_key(),
        support::scope(&["append", "read"]),
        3600,
        1,
    )?;
    runtime.create_root("root", &root, support::limits(10))?;
    let service = WorkerService::new(runtime.clone());
    let mut frames = Vec::new();
    for name in ["reader", "writer"] {
        let child = support::child(
            &root,
            &support::parent_key(),
            name,
            &Keypair::generate(),
            support::scope(&["append"]),
        )?;
        runtime.spawn("root", name, &child)?;
        assert_eq!(
            runtime
                .process(name)?
                .capability
                .aggregate_invocation_budget,
            root.aggregate_invocation_budget
        );
        let credential = service.issue_credential(name, root.expires_at)?;
        frames.push(serde_json::to_vec(&json!({
            "protocol": PROTOCOL, "credential": credential.expose_secret(),
            "operation": {"op": "invoke", "operation_key": "publish", "server_id": "tools",
                "tool_name": "append", "arguments": {"worker": name}}
        }))?);
    }
    let (first, second) = tokio::join!(
        service.handle_frame(&frames[0]),
        service.handle_frame(&frames[1])
    );
    let replies = [first, second];
    let mut winner = None;
    let mut allowed = 0;
    let mut denied = 0;
    for (index, reply) in replies.iter().enumerate() {
        let response: Value = serde_json::from_slice(reply)?;
        match response["result"]["verdict"].as_str() {
            Some("allow") => {
                allowed += 1;
                winner = Some(index);
            }
            Some("deny") => denied += 1,
            _ => return Err(format!("unexpected worker reply: {response}").into()),
        }
        let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_str(
            response["result"]["receipt_json"]
                .as_str()
                .ok_or("receipt")?,
        )?;
        assert!(receipt.verify_signature()?);
    }
    assert_eq!((allowed, denied), (1, 1));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    // The process ceiling is ten, so it cannot explain the second refusal.
    assert_eq!(runtime.process("root")?.tree_calls, 2);
    let winner = winner.ok_or("no winner")?;
    drop(service);
    drop(runtime);
    drop(kernel);

    let kernel = support::kernel(directory.path(), Box::new(Tool(effects.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel)?;
    let service = WorkerService::new(runtime.clone());
    assert_eq!(service.handle_frame(&frames[winner]).await, replies[winner]);
    let mut another: Value = serde_json::from_slice(&frames[1 - winner])?;
    another["operation"]["operation_key"] = json!("publish-again");
    let refused: Value =
        serde_json::from_slice(&service.handle_frame(&serde_json::to_vec(&another)?).await)?;
    assert_eq!(refused["result"]["verdict"], "deny", "{refused}");
    assert_eq!(runtime.process("root")?.tree_calls, 3);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn aggregate_issuance_requires_the_existing_durable_authority() -> Result {
    let kernel = ChioKernel::new(support::config());
    assert!(kernel
        .issue_aggregate_family_root(
            &support::parent_key().public_key(),
            support::scope(&["append"]),
            300,
            1,
        )
        .is_err());
    Ok(())
}
