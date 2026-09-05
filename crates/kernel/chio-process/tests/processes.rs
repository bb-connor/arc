mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core_types::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallOutput, ToolServerConnection, Verdict,
};
use chio_process::{ProcessError, ProcessRuntime, ProcessState};
use serde_json::{json, Value};
use support::{child, kernel, parent_key, root, scope, Result};

struct Server {
    calls: Arc<AtomicUsize>,
    entered: Option<Arc<tokio::sync::Notify>>,
    release: Option<Arc<tokio::sync::Notify>>,
}

#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(entered) = &self.entered {
            entered.notify_one();
        }
        if let Some(release) = &self.release {
            release.notified().await;
        }
        Ok(arguments)
    }
}

fn server(calls: &Arc<AtomicUsize>) -> Box<Server> {
    Box::new(Server {
        calls: calls.clone(),
        entered: None,
        release: None,
    })
}

#[tokio::test]
async fn logical_call_replays_original_signed_receipt_after_kernel_restart() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (request, first_receipt) = {
        let kernel = kernel(dir.path(), server(&calls))?;
        let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
        root(&runtime, &kernel, 1)?;
        let request = runtime.tool_request(
            "root",
            "publish",
            "tools",
            "append",
            json!({"text": "hello"}),
        )?;
        let first = runtime.invoke("root", "publish", &request).await?;
        assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
        assert!(first.receipt.verify_signature()?);
        runtime.checkpoint("root", 0, json!({"phase": "published"}))?;
        (request, serde_json::to_value(first.receipt)?)
    };
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel)?;
    let recovered = runtime.invoke("root", "publish", &request).await?;
    assert_eq!(recovered.verdict, Verdict::Allow, "{:?}", recovered.reason);
    assert_eq!(serde_json::to_value(recovered.receipt)?, first_receipt);
    assert_eq!(
        recovered.output,
        Some(ToolCallOutput::Value(json!({"text": "hello"})))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        runtime.process("root")?.checkpoint.value,
        json!({"phase": "published"})
    );
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}

#[tokio::test]
async fn children_share_a_durable_tree_ceiling_and_cannot_widen_scope() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let parent = root(&runtime, &kernel, 2)?;
    for id in ["worker-a", "worker-b"] {
        let cap = child(
            &parent,
            &parent_key(),
            id,
            &Keypair::generate(),
            scope(&["read"]),
        )?;
        runtime.spawn("root", id, &cap)?;
        let request =
            runtime.tool_request(id, "research", "tools", "read", json!({"worker": id}))?;
        let response = runtime.invoke(id, "research", &request).await?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.receipt.verify_signature()?);
    }
    let request = runtime.tool_request("root", "third", "tools", "append", json!({}))?;
    assert!(matches!(
        runtime.invoke("root", "third", &request).await,
        Err(ProcessError::Limit(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(runtime.process("worker-a")?.tree_calls, 2);
    // A correctly signed token for a different process is still not a child.
    assert!(runtime.spawn("root", "forged", &parent).is_err());
    Ok(())
}

#[tokio::test]
async fn narrowed_child_is_denied_by_the_real_kernel() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let parent = root(&runtime, &kernel, 3)?;
    let cap = child(
        &parent,
        &parent_key(),
        "reader",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &cap)?;
    let request = runtime.tool_request("reader", "write", "tools", "append", json!({}))?;
    let response = runtime.invoke("reader", "write", &request).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn conflicting_replay_and_capability_substitution_never_dispatch() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&runtime, &kernel, 3)?;
    let mut request = runtime.tool_request("root", "write", "tools", "append", json!({"v": 1}))?;
    assert_eq!(
        runtime.invoke("root", "write", &request).await?.verdict,
        Verdict::Allow
    );
    request.arguments = json!({"v": 2});
    assert!(matches!(
        runtime.invoke("root", "write", &request).await,
        Err(ProcessError::Conflict)
    ));
    request = runtime.tool_request("root", "other", "tools", "append", json!({}))?;
    request.capability =
        kernel.issue_capability(&Keypair::generate().public_key(), scope(&["append"]), 300)?;
    request.agent_id = request.capability.subject.to_hex();
    assert!(matches!(
        runtime.invoke("root", "other", &request).await,
        Err(ProcessError::Conflict)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_opens_cannot_overspend_the_last_call() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let a = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let b = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&a, &kernel, 1)?;
    let req_a = a.tool_request("root", "a", "tools", "append", json!({}))?;
    let req_b = b.tool_request("root", "b", "tools", "append", json!({}))?;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let left = tokio::spawn(async move {
        barrier.wait().await;
        a.invoke("root", "a", &req_a).await
    });
    let right = tokio::spawn(async move {
        other_barrier.wait().await;
        b.invoke("root", "b", &req_b).await
    });
    let (left, right) = (left.await?, right.await?);
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(ProcessError::Limit(_))) || matches!(right, Err(ProcessError::Limit(_)))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn checkpoints_use_compare_and_swap_and_cancel_covers_descendants() -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), server(&Arc::new(AtomicUsize::new(0))))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let parent = root(&runtime, &kernel, 10)?;
    let child_key = Keypair::generate();
    let cap = child(
        &parent,
        &parent_key(),
        "child",
        &child_key,
        scope(&["read"]),
    )?;
    runtime.spawn("root", "child", &cap)?;
    let grandchild = child(
        &cap,
        &child_key,
        "grandchild",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    runtime.spawn("child", "grandchild", &grandchild)?;
    let other = ProcessRuntime::open(dir.path().join("process.db"), kernel)?;
    assert_eq!(
        runtime.checkpoint("child", 0, json!({"step": 1}))?.revision,
        1
    );
    assert!(matches!(
        other.checkpoint("child", 0, json!({"step": 2})),
        Err(ProcessError::CheckpointConflict)
    ));
    assert_eq!(runtime.cancel("child")?, 2);
    assert_eq!(runtime.cancel("child")?, 0);
    assert_eq!(other.process("root")?.state, ProcessState::Running);
    assert_eq!(other.process("grandchild")?.state, ProcessState::Cancelled);
    assert!(matches!(
        other.checkpoint("child", 1, json!({})),
        Err(ProcessError::Cancelled(_))
    ));
    assert!(matches!(
        runtime.spawn("child", "later", &grandchild),
        Err(ProcessError::Cancelled(_))
    ));
    Ok(())
}

#[tokio::test]
async fn cancellation_withholds_inflight_output_and_prevents_further_calls() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let kernel = kernel(
        dir.path(),
        Box::new(Server {
            calls: calls.clone(),
            entered: Some(entered.clone()),
            release: Some(release.clone()),
        }),
    )?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&runtime, &kernel, 10)?;
    let worker = runtime.clone();
    let request = runtime.tool_request("root", "publish", "tools", "append", json!({}))?;
    let task = tokio::spawn(async move { worker.invoke("root", "publish", &request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await?;
    runtime.cancel("root")?;
    release.notify_one();
    assert!(matches!(task.await?, Err(ProcessError::Cancelled(_))));
    let another = runtime.tool_request("root", "next", "tools", "append", json!({}))?;
    assert!(matches!(
        runtime.invoke("root", "next", &another).await,
        Err(ProcessError::Cancelled(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn opening_against_a_fresh_authority_or_ephemeral_kernel_is_rejected() -> Result {
    let a = tempfile::tempdir()?;
    let b = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let first = kernel(a.path(), server(&calls))?;
    ProcessRuntime::open(a.path().join("process.db"), first)?;
    let fresh = kernel(b.path(), server(&calls))?;
    assert!(matches!(
        ProcessRuntime::open(a.path().join("process.db"), fresh),
        Err(ProcessError::Configuration(_))
    ));
    let ephemeral = Arc::new(ChioKernel::new(support::config()));
    assert!(matches!(
        ProcessRuntime::open(a.path().join("process.db"), ephemeral),
        Err(ProcessError::Configuration(_))
    ));
    Ok(())
}

#[tokio::test]
async fn never_invoked_ancestors_are_restored_before_a_grandchild_runs() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    {
        let kernel = kernel(dir.path(), server(&calls))?;
        let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
        let parent = root(&runtime, &kernel, 3)?;
        let key = Keypair::generate();
        let cap = child(&parent, &parent_key(), "child", &key, scope(&["read"]))?;
        runtime.spawn("root", "child", &cap)?;
        let grandchild = child(
            &cap,
            &key,
            "grandchild",
            &Keypair::generate(),
            scope(&["read"]),
        )?;
        runtime.spawn("child", "grandchild", &grandchild)?;
    }
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel)?;
    let request =
        runtime.tool_request("grandchild", "read", "tools", "read", json!({"depth": 2}))?;
    let response = runtime.invoke("grandchild", "read", &request).await?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}

#[tokio::test]
async fn a_duplicate_while_dispatch_is_live_does_not_create_a_second_effect() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let kernel = kernel(
        dir.path(),
        Box::new(Server {
            calls: calls.clone(),
            entered: Some(entered.clone()),
            release: Some(release.clone()),
        }),
    )?;
    let a = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let b = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&a, &kernel, 1)?;
    let request = a.tool_request("root", "publish", "tools", "append", json!({}))?;
    let concurrent_request = request.clone();
    let first = tokio::spawn(async move { a.invoke("root", "publish", &concurrent_request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await?;
    let duplicate = b.invoke("root", "publish", &request).await?;
    assert_eq!(duplicate.verdict, Verdict::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.notify_one();
    let original = first.await??;
    assert_eq!(original.verdict, Verdict::Allow);
    let replay = b.invoke("root", "publish", &request).await?;
    assert_eq!(
        serde_json::to_value(replay.receipt)?,
        serde_json::to_value(original.receipt)?
    );
    assert_eq!(b.process("root")?.tree_calls, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn process_count_depth_and_identity_reuse_are_bounded() -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), server(&Arc::new(AtomicUsize::new(0))))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let cap =
        kernel.issue_capability(&parent_key().public_key(), scope(&["append", "read"]), 300)?;
    let limits = chio_process::ProcessLimits {
        max_processes: 2,
        max_depth: 1,
        max_calls: 1,
    };
    runtime.create_root("root", &cap, limits)?;
    runtime.create_root("root", &cap, limits)?;
    assert!(matches!(
        runtime.create_root("root", &cap, support::limits(20)),
        Err(ProcessError::Conflict)
    ));
    let key = Keypair::generate();
    let narrow = child(&cap, &parent_key(), "child", &key, scope(&["read"]))?;
    runtime.spawn("root", "child", &narrow)?;
    let grandchild = child(
        &narrow,
        &key,
        "grandchild",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    assert!(matches!(
        runtime.spawn("child", "grandchild", &grandchild),
        Err(ProcessError::Limit("depth"))
    ));
    runtime.cancel("child")?;
    assert!(matches!(
        runtime.spawn("root", "sibling", &narrow),
        Err(ProcessError::Limit("process count"))
    ));
    assert!(matches!(
        runtime.spawn("root", "child", &narrow),
        Err(ProcessError::Cancelled(_))
    ));
    assert_ne!(
        runtime.request_id("a:b", "c")?,
        runtime.request_id("a", "b:c")?
    );
    assert!(runtime.request_id("root", "").is_err());
    assert!(runtime.checkpoint("root", u64::MAX, json!({})).is_err());
    Ok(())
}

#[test]
fn dormant_parents_cannot_overallocate_sibling_shares_and_cancellation_does_not_reset_them(
) -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), server(&Arc::new(AtomicUsize::new(0))))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let parent = root(&runtime, &kernel, 100)?;
    for index in 0..10 {
        let id = format!("child-{index}");
        let cap = child(
            &parent,
            &parent_key(),
            &id,
            &Keypair::generate(),
            scope(&["read"]),
        )?;
        runtime.spawn("root", &id, &cap)?;
    }
    assert_eq!(runtime.process("root")?.tree_calls, 0);
    runtime.cancel("child-0")?;
    let other = ProcessRuntime::open(dir.path().join("process.db"), kernel)?;
    let extra = child(
        &parent,
        &parent_key(),
        "extra",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    assert!(matches!(
        other.spawn("root", "extra", &extra),
        Err(ProcessError::Limit("sibling budget shares"))
    ));
    Ok(())
}
