#![cfg(all(feature = "worker-server", unix))]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core_types::crypto::canonical_json_bytes;
use chio_kernel::{
    KernelError, NestedFlowBridge, RuntimeAdmissionContext, RuntimeAdmissionDecision,
    RuntimeAdmissionHook, ToolServerConnection, Verdict,
};
use chio_process::worker::{WorkerService, PROTOCOL};
use chio_process::{ProcessError, ProcessLaunchReceipt, ProcessRoute, ProcessRuntime};
use serde_json::{json, Value};
use support::Result;

struct Tool(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for Tool {
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

// The spy checks only transport of the host-selected values. Real signed swarm
// verification and physical continuation custody belong to runtime-core tests.
struct RouteHook;

impl RuntimeAdmissionHook for RouteHook {
    fn name(&self) -> &str {
        "test-host-route"
    }
    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> std::result::Result<RuntimeAdmissionDecision, KernelError> {
        let route = context.extra_metadata.and_then(|value| value.get("route"));
        if route == Some(&expected_route()) {
            Ok(RuntimeAdmissionDecision::allow(None))
        } else {
            Ok(RuntimeAdmissionDecision::deny("host route mismatch", None))
        }
    }
}

fn expected_route() -> Value {
    json!({"bridge": "mcp", "protocolTarget": "mcp://local/tools", "selectedRoute": "mcp:tools"})
}

fn routes() -> Result<[(String, ProcessRoute); 1]> {
    Ok([(
        "tools".into(),
        ProcessRoute::new("mcp", "mcp://local/tools", "mcp:tools")?,
    )])
}

// These references test host attribution and recovery, not cage authenticity.
fn launch(id: char) -> Result<[(String, ProcessLaunchReceipt); 1]> {
    Ok([(
        "tools".into(),
        ProcessLaunchReceipt::new(id.to_string().repeat(64), "d".repeat(64))?,
    )])
}

fn kernel(
    path: &std::path::Path,
    effects: Arc<AtomicUsize>,
) -> Result<Arc<chio_kernel::ChioKernel>> {
    let mut kernel = support::kernel(path, Box::new(Tool(effects)))?;
    Arc::get_mut(&mut kernel)
        .ok_or("kernel is shared before configuration")?
        .set_runtime_admission_hook(Arc::new(RouteHook));
    Ok(kernel)
}

#[tokio::test]
async fn authenticated_worker_context_cannot_replace_host_route_or_process_attribution() -> Result {
    let dir = tempfile::tempdir()?;
    let effects = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), effects.clone())?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?
        .with_routes(routes()?)?
        .with_launch_receipts(launch('a')?)?;
    let capability = support::root(&runtime, &kernel, 4)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("root", capability.expires_at)?;
    let mut frame = json!({
        "protocol": PROTOCOL, "credential": token.expose_secret(),
        "operation": {"op": "invoke", "operation_key": "effect", "server_id": "tools",
            "tool_name": "append", "arguments": {"text": "checked"},
            "governed_intent": {"id": "intent", "server_id": "tools", "tool_name": "append",
                "purpose": "a routed task", "context": {
                    "route": {"bridge": "forged", "protocolTarget": "mcp://attacker", "selectedRoute": "other"},
                    "chio_process": {"process_id": "another-worker"}
                }}
        }
    });
    frame["operation"]["governed_intent"]["context"]["native_launch"] =
        json!({"receipt_id": "forged", "receipt_sha256": "forged"});
    let response: Value =
        serde_json::from_slice(&service.handle_frame(&serde_json::to_vec(&frame)?).await)?;
    assert_eq!(response["result"]["verdict"], "allow", "{response}");
    let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_str(
        response["result"]["receipt_json"]
            .as_str()
            .ok_or("missing receipt")?,
    )?;
    assert!(receipt.verify_signature()?);
    let metadata = receipt.metadata.ok_or("missing signed attribution")?;
    assert_eq!(metadata["route"], expected_route());
    assert_eq!(metadata["chio_process"]["process_id"], "root");
    assert_eq!(metadata["chio_process"]["runtime_id"], runtime.runtime_id());
    assert_eq!(
        metadata["native_launch"],
        serde_json::to_value(&launch('a')?[0].1)?
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);

    // Route selection is absent from the worker protocol, even with valid auth.
    frame["operation"]["route"] = expected_route();
    let denied: Value =
        serde_json::from_slice(&service.handle_frame(&serde_json::to_vec(&frame)?).await)?;
    assert_eq!(denied["error"]["code"], "invalid_request");
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn reopen_requires_original_route_and_preserves_completed_receipt_without_second_effect(
) -> Result {
    let dir = tempfile::tempdir()?;
    let effects = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), effects.clone())?;
    let journal = dir.path().join("process.db");
    let runtime = ProcessRuntime::open(&journal, kernel.clone())?
        .with_routes(routes()?)?
        .with_launch_receipts(launch('a')?)?;
    support::root(&runtime, &kernel, 4)?;
    let request =
        runtime.tool_request("root", "effect", "tools", "append", json!({"text": "one"}))?;
    let first = runtime
        .invoke_known_only("root", "effect", &request)
        .await?;
    assert_eq!(first.verdict, Verdict::Allow, "{first:?}");
    drop(runtime);

    let alternatives = [
        None,
        Some(ProcessRoute::new(
            "other",
            "mcp://local/tools",
            "mcp:tools",
        )?),
        Some(ProcessRoute::new("mcp", "mcp://other/tools", "mcp:tools")?),
        Some(ProcessRoute::new("mcp", "mcp://local/tools", "mcp:other")?),
    ];
    for route in alternatives {
        let mut reopened = ProcessRuntime::open(&journal, kernel.clone())?;
        if let Some(route) = route {
            reopened = reopened.with_routes([("tools".into(), route)])?;
        }
        assert!(matches!(
            reopened.invoke_known_only("root", "effect", &request).await,
            Err(ProcessError::Conflict)
        ));
        assert_eq!(reopened.process("root")?.tree_calls, 1);
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }
    let reopened = ProcessRuntime::open(&journal, kernel)?
        .with_routes(routes()?)?
        .with_launch_receipts(launch('b')?)?;
    let replay = reopened
        .invoke_known_only("root", "effect", &request)
        .await?;
    assert_eq!(
        canonical_json_bytes(&first.receipt)?,
        canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let request =
        reopened.tool_request("root", "second", "tools", "append", json!({"text": "two"}))?;
    let second = reopened
        .invoke_known_only("root", "second", &request)
        .await?;
    assert_eq!(second.verdict, Verdict::Allow);
    assert_eq!(
        second.receipt.metadata.as_ref().ok_or("missing metadata")?["native_launch"],
        serde_json::to_value(&launch('b')?[0].1)?
    );
    assert_eq!(
        replay.receipt.metadata.as_ref().ok_or("missing metadata")?["native_launch"],
        serde_json::to_value(&launch('a')?[0].1)?
    );
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn route_absence_denies_before_effect_and_legacy_binding_cannot_gain_a_route() -> Result {
    let dir = tempfile::tempdir()?;
    let effects = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), effects.clone())?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 4)?;
    let request = runtime.tool_request("root", "effect", "tools", "append", json!({}))?;
    let denied = runtime.invoke("root", "effect", &request).await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature()?);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let routed = runtime.with_routes(routes()?)?;
    assert!(matches!(
        routed.invoke("root", "effect", &request).await,
        Err(ProcessError::Conflict)
    ));
    let next = routed.tool_request("root", "new-effect", "tools", "append", json!({}))?;
    assert_eq!(
        routed.invoke("root", "new-effect", &next).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn ambiguous_or_malformed_host_routes_refuse_configuration() -> Result {
    for invalid in ["", " mcp", "mcp ", "mcp\n", "mcp\0"] {
        assert!(ProcessRoute::new(invalid, "mcp://local/tools", "mcp:tools").is_err());
        assert!(ProcessRoute::new("mcp", invalid, "mcp:tools").is_err());
        assert!(ProcessRoute::new("mcp", "mcp://local/tools", invalid).is_err());
    }
    assert!(ProcessRoute::new("mcp", "a".repeat(4097), "mcp:tools").is_err());
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), Arc::new(AtomicUsize::new(0)))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel)?;
    let route = routes()?[0].clone();
    for invalid in ["", "Z", " "] {
        assert!(ProcessLaunchReceipt::new(invalid.repeat(64), "d".repeat(64)).is_err());
    }
    assert!(ProcessLaunchReceipt::new("f".into(), "d".repeat(64)).is_err());
    let receipt = launch('a')?[0].clone();
    assert!(runtime
        .clone()
        .with_launch_receipts([receipt.clone(), receipt])
        .is_err());
    assert!(runtime.with_routes([route.clone(), route]).is_err());
    Ok(())
}
