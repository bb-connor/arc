//! Research acceptance for the operation-identity seam used by recovery offers.
//! These tests exercise the real process store and kernel. The signed fixture
//! checks immutable request binding only; it is not a verified disclosure grant.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core_types::{Keypair, SignedDeclassificationGrant};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::{ProcessError, ProcessRuntime};
use serde_json::{json, Value};
use support::{child, kernel, parent_key, root, scope, Result};

struct CountingServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
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
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

fn binding_fixture(capability_id: &str) -> Result<SignedDeclassificationGrant> {
    // Synthetic artifact, intentionally not installed as authority. The process
    // rejects its addition before reaching any disclosure-verification path.
    let body = serde_json::from_value(json!({
        "domain_version": 1, "grant_id": "lab-grant",
        "capability_id": capability_id, "tenant_id": "lab-tenant",
        "subject_id": "lab-subject", "agent_id": "lab-agent", "session_id": "lab-session",
        "source_label_hash": vec![1; 32],
        "target_label": {"kind": "known", "owners": {}, "compartments": []},
        "destination_id": "tools", "tool_name": "append", "purpose": "lab-binding",
        "request_hash": vec![2; 32], "issued_at_unix_seconds": 100,
        "expires_at_unix_seconds": 200, "authority_key_id": "lab-authority"
    }))?;
    Ok(SignedDeclassificationGrant::sign(body, &support::issuer())?)
}

#[tokio::test]
async fn a_denied_operation_cannot_be_rewritten_with_a_grant_after_store_reopen() -> Result {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(directory.path(), Box::new(CountingServer(calls.clone())))?;
    let database = directory.path().join("process.db");
    let runtime = ProcessRuntime::open(&database, kernel.clone())?;
    let parent = root(&runtime, &kernel, 4)?;
    let reader = child(
        &parent,
        &parent_key(),
        "reader",
        &Keypair::from_seed(&[62; 32]),
        scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &reader)?;
    let original = runtime.tool_request("reader", "denied", "tools", "append", json!({}))?;
    let denied = runtime.invoke("reader", "denied", &original).await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature()?);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(runtime);

    // Reopen durable process state while retaining the same serving kernel.
    let reopened = ProcessRuntime::open(&database, kernel)?;
    let mut changed = original.clone();
    changed.declassification_grant = Some(binding_fixture(&reader.id)?);
    assert!(matches!(
        reopened.invoke("reader", "denied", &changed).await,
        Err(ProcessError::Conflict)
    ));
    assert_eq!(reopened.process("root")?.tree_calls, 1);
    let replay = reopened.invoke("reader", "denied", &original).await?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(replay.request_id, denied.request_id);
    assert!(replay.receipt.verify_signature()?);

    // A continuation has a distinct identity and spends another logical call.
    // It still cannot repair missing capability authority by carrying a grant.
    let mut continuation = reopened.tool_request(
        "reader",
        "denied-continuation-1",
        "tools",
        "append",
        json!({}),
    )?;
    continuation.declassification_grant = Some(binding_fixture(&reader.id)?);
    assert_ne!(continuation.request_id, original.request_id);
    let denied_again = reopened
        .invoke("reader", "denied-continuation-1", &continuation)
        .await?;
    assert_eq!(denied_again.verdict, Verdict::Deny);
    assert!(denied_again.receipt.verify_signature()?);
    assert_eq!(reopened.process("root")?.tree_calls, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn attaching_a_grant_to_a_completed_operation_cannot_repeat_its_effect() -> Result {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(directory.path(), Box::new(CountingServer(calls.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    let capability = root(&runtime, &kernel, 2)?;
    let original = runtime.tool_request("root", "publish", "tools", "append", json!({}))?;
    let completed = runtime.invoke("root", "publish", &original).await?;
    assert_eq!(completed.verdict, Verdict::Allow);
    assert!(completed.receipt.verify_signature()?);
    let mut changed = original.clone();
    changed.declassification_grant = Some(binding_fixture(&capability.id)?);
    assert!(matches!(
        runtime.invoke("root", "publish", &changed).await,
        Err(ProcessError::Conflict)
    ));
    let recovered = runtime.invoke("root", "publish", &original).await?;
    assert_eq!(recovered.request_id, completed.request_id);
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}
