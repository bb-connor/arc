#![cfg(all(feature = "worker-server", unix))]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core_types::crypto::Keypair;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::worker::{
    WorkerServer, WorkerService, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL,
};
use chio_process::{ProcessError, ProcessRuntime};
use serde_json::{json, Value};
use support::{child, kernel, parent_key, root, scope, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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
        if arguments.get("large") == Some(&json!(true)) {
            return Ok(json!("x".repeat(MAX_RESPONSE_BYTES)));
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

fn frame(secret: &str, operation: Value) -> Vec<u8> {
    json!({"protocol": PROTOCOL, "credential": secret, "operation": operation})
        .to_string()
        .into_bytes()
}

fn invoke(key: &str) -> Value {
    json!({"op": "invoke", "operation_key": key, "server_id": "tools", "tool_name": "read", "arguments": {"text": "hi"}})
}

fn governed_invoke(key: &str, context: Value) -> Value {
    let mut operation = invoke(key);
    operation["governed_intent"] = json!({
        "id": "worker-task-intent", "server_id": "tools", "tool_name": "read",
        "purpose": "read for an authenticated task", "context": context
    });
    operation
}

#[tokio::test]
async fn governed_worker_context_reaches_required_swarm_kernel_without_granting_authority() -> Result
{
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut kernel = kernel(dir.path(), server(&calls))?;
    Arc::get_mut(&mut kernel)
        .ok_or("kernel must be exclusively owned during configuration")?
        .require_swarm_admission();
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let parent = root(&runtime, &kernel, 4)?;
    let cap = child(
        &parent,
        &parent_key(),
        "reader",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &cap)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("reader", cap.expires_at)?;
    let operation = governed_invoke("task-read", json!({"chioSwarm": {}}));
    let denied = request(&service, token.expose_secret(), operation.clone()).await?;
    assert_eq!(denied["ok"], true, "{denied}");
    assert_eq!(denied["result"]["verdict"], "deny", "{denied}");
    let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_str(
        denied["result"]["receipt_json"]
            .as_str()
            .ok_or("missing signed denial")?,
    )?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.capability_id, cap.id);
    assert_eq!(
        receipt.metadata.as_ref().ok_or("missing denial metadata")?["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let replay = request(&service, token.expose_secret(), operation).await?;
    // A compensated pre-dispatch denial retains the operation, not a tool
    // outcome. The kernel signs a fresh refusal; it must not retry dispatch.
    assert_eq!(replay["result"]["verdict"], "deny", "{replay}");
    assert_eq!(
        replay["result"]["request_id"],
        denied["result"]["request_id"]
    );
    let replay_receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_str(
        replay["result"]["receipt_json"]
            .as_str()
            .ok_or("missing replay denial")?,
    )?;
    assert!(replay_receipt.verify_signature()?);
    assert_eq!(replay_receipt.capability_id, cap.id);
    assert_eq!(
        replay_receipt
            .metadata
            .as_ref()
            .ok_or("missing replay metadata")?["governed_transaction"],
        receipt.metadata.as_ref().ok_or("missing metadata")?["governed_transaction"]
    );
    for changed in [
        invoke("task-read"),
        governed_invoke("task-read", json!({"chioSwarm": {"taskId": "other"}})),
    ] {
        assert_eq!(
            request(&service, token.expose_secret(), changed).await?["error"]["code"],
            "conflict"
        );
    }
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn governed_worker_completed_outcome_reopens_with_identical_intent_and_receipt() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let path = dir.path().join("process.db");
    let runtime = ProcessRuntime::open(&path, kernel.clone())?;
    let cap = root(&runtime, &kernel, 4)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("root", cap.expires_at)?;
    // Ordinary governed intent exercises transport and durable outcomes, not
    // swarm authority acceptance. That profile requires a real verifying hook.
    let operation = governed_invoke("task-read", json!({"task": "read λ"}));
    let first = request(&service, token.expose_secret(), operation.clone()).await?;
    assert_eq!(first["result"]["verdict"], "allow", "{first}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(service);
    drop(runtime);
    drop(kernel);
    let reopened_kernel = support::kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(path, reopened_kernel)?;
    let service = WorkerService::new(runtime.clone());
    service.revoke_credentials("root")?;
    let fresh_token = service.issue_credential("root", cap.expires_at)?;
    assert_eq!(
        request(&service, token.expose_secret(), operation.clone()).await?["error"]["code"],
        "unauthenticated"
    );
    let replay = request(&service, fresh_token.expose_secret(), operation).await?;
    assert_eq!(
        replay["result"]["receipt_json"],
        first["result"]["receipt_json"]
    );
    let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_str(
        replay["result"]["receipt_json"]
            .as_str()
            .ok_or("missing retained receipt")?,
    )?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.capability_id, cap.id);
    for changed in [
        invoke("task-read"),
        governed_invoke("task-read", json!({"task": "other"})),
    ] {
        assert_eq!(
            request(&service, fresh_token.expose_secret(), changed).await?["error"]["code"],
            "conflict"
        );
    }
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn governed_worker_input_cannot_bypass_authentication_or_select_a_capability() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let cap = root(&runtime, &kernel, 4)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("root", cap.expires_at)?;
    let operation = governed_invoke("task-read", json!({"chioSwarm": {}}));
    let forged = request(&service, &"a".repeat(64), operation.clone()).await?;
    assert_eq!(forged["error"]["code"], "unauthenticated", "{forged}");
    let mut substituted = operation.clone();
    substituted["capability"] = serde_json::to_value(&cap)?;
    assert_eq!(
        request(&service, token.expose_secret(), substituted).await?["error"]["code"],
        "invalid_request"
    );
    for invalid in [
        json!(false),
        json!([]),
        json!({"context": {"chioSwarm": {}}}),
    ] {
        let mut malformed = operation.clone();
        malformed["governed_intent"] = invalid;
        assert_eq!(
            request(&service, token.expose_secret(), malformed).await?["error"]["code"],
            "invalid_request"
        );
    }
    assert_eq!(runtime.process("root")?.tree_calls, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn request(service: &WorkerService, secret: &str, operation: Value) -> Result<Value> {
    Ok(serde_json::from_slice(
        &service.handle_frame(&frame(secret, operation)).await,
    )?)
}

#[tokio::test]
async fn worker_recovery_policy_is_bound_to_the_logical_operation() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let capability = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let token = service.issue_credential("root", capability.expires_at)?;
    let secret = token.expose_secret();
    let mut known = invoke("known");
    known["known_outcome_only"] = json!(true);
    let first = request(&service, secret, known.clone()).await?;
    assert_eq!(first["ok"], true);
    let replay = request(&service, secret, known).await?;
    assert_eq!(
        first["result"]["receipt_json"],
        replay["result"]["receipt_json"]
    );
    assert_eq!(
        request(&service, secret, invoke("known")).await?["error"]["code"],
        "conflict"
    );
    assert_eq!(
        request(&service, secret, invoke("normal")).await?["ok"],
        true
    );
    let mut changed = invoke("normal");
    changed["known_outcome_only"] = json!(true);
    assert_eq!(
        request(&service, secret, changed).await?["error"]["code"],
        "conflict"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn guest_identity_is_fixed_and_admin_operations_are_absent() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let parent = root(&runtime, &kernel, 4)?;
    let cap = child(
        &parent,
        &parent_key(),
        "reader",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &cap)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("reader", cap.expires_at)?;
    let secret = token.expose_secret();
    assert_eq!(format!("{token:?}"), "WorkerCredential([REDACTED])");
    let snapshot = request(&service, secret, json!({"op": "inspect"})).await?;
    assert_eq!(snapshot["result"]["process_id"], "reader");
    assert!(snapshot["result"].get("capability").is_none());
    for operation in [
        json!({"op": "inspect", "process_id": "root"}),
        json!({"op": "cancel", "process_id": "root"}),
        json!({"op": "spawn"}),
        json!({"op": "issue_credential"}),
        json!({"op": "invoke", "capability": parent}),
    ] {
        assert_eq!(
            request(&service, secret, operation).await?["error"]["code"],
            "invalid_request"
        );
    }
    let forged = "a".repeat(64);
    assert_eq!(
        request(&service, &forged, invoke("forged")).await?["error"]["code"],
        "unauthenticated"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.process("root")?.tree_calls, 0);
    let allowed = request(&service, secret, invoke("allowed")).await?;
    assert_eq!(allowed["result"]["verdict"], "allow", "{allowed}");
    let mut forbidden = invoke("forbidden");
    forbidden["tool_name"] = json!("append");
    let denied = request(&service, secret, forbidden).await?;
    assert_eq!(denied["result"]["verdict"], "deny", "{denied}");
    let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_str(
        denied["result"]["receipt_json"]
            .as_str()
            .ok_or("missing receipt")?,
    )?;
    assert!(receipt.verify_signature()?);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let checkpoint = request(
        &service,
        secret,
        json!({"op": "checkpoint", "expected_revision": "0", "value": [1,2]}),
    )
    .await?;
    assert_eq!(checkpoint["result"]["revision"], "1");
    assert_eq!(
        request(
            &service,
            secret,
            json!({"op": "checkpoint", "expected_revision": "0", "value": []})
        )
        .await?["error"]["code"],
        "checkpoint_conflict"
    );
    request(&service, secret, json!({"op": "cancel"})).await?;
    let cancelled = request(&service, secret, json!({"op": "inspect"})).await?;
    assert_eq!(cancelled["ok"], true, "{cancelled}");
    assert_eq!(cancelled["result"]["state"], "cancelled");
    assert_eq!(cancelled["result"]["checkpoint"]["value"], json!([1, 2]));
    assert!(matches!(
        runtime.put_blob("reader", b"after cancellation"),
        Err(ProcessError::Cancelled(_))
    ));
    assert_eq!(
        request(&service, secret, invoke("after-cancel")).await?["error"]["code"],
        "cancelled"
    );
    assert_eq!(
        runtime.process("root")?.state,
        chio_process::ProcessState::Running
    );
    service.revoke_credentials("reader")?;
    assert_eq!(
        request(&service, secret, json!({"op": "inspect"})).await?["error"]["code"],
        "unauthenticated"
    );
    assert!(matches!(
        service.revoke_credentials("absent"),
        Err(ProcessError::NotFound(_))
    ));
    Ok(())
}

#[tokio::test]
async fn credential_expiry_and_revocation_are_durable() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (secret, first) = {
        let kernel = kernel(dir.path(), server(&calls))?;
        let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
        let cap = root(&runtime, &kernel, 2)?;
        let service = WorkerService::new(runtime);
        assert!(matches!(
            service.issue_credential("root", 1),
            Err(ProcessError::Invalid(_))
        ));
        assert!(matches!(
            service.issue_credential("root", cap.expires_at + 1),
            Err(ProcessError::Invalid(_))
        ));
        let secret = service
            .issue_credential("root", cap.expires_at)?
            .expose_secret()
            .to_owned();
        let first = request(&service, &secret, invoke("one")).await?;
        (secret, first)
    };
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel)?;
    let service = WorkerService::new(runtime);
    assert_eq!(request(&service, &secret, invoke("one")).await?, first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let db = rusqlite::Connection::open(dir.path().join("process.db"))?;
    let hash: String = db.query_row("SELECT credential_hash FROM worker_credentials", [], |r| {
        r.get(0)
    })?;
    assert_ne!(hash, secret);
    assert_eq!(hash, chio_core_types::crypto::sha256_hex(secret.as_bytes()));
    assert_eq!(service.revoke_credentials("root")?, 1);
    assert_eq!(
        request(&service, &secret, invoke("one")).await?["error"]["code"],
        "unauthenticated"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn revocation_during_dispatch_withholds_output_and_a_new_credential_recovers() -> Result {
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
    let cap = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let credential = service.issue_credential("root", cap.expires_at)?;
    let bytes = frame(credential.expose_secret(), invoke("one"));
    let task_service = service.clone();
    let task = tokio::spawn(async move { task_service.handle_frame(&bytes).await });
    entered.notified().await;
    service.revoke_credentials("root")?;
    release.notify_one();
    let response: Value = serde_json::from_slice(&task.await?)?;
    assert_eq!(response["error"]["code"], "unauthenticated");
    let replacement = service.issue_credential("root", cap.expires_at)?;
    let recovered = request(&service, replacement.expose_secret(), invoke("one")).await?;
    assert_eq!(recovered["result"]["verdict"], "allow", "{recovered}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn oversized_response_retains_the_original_effect_identity() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let cap = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("root", cap.expires_at)?;
    let mut operation = invoke("large");
    operation["arguments"] = json!({"large": true});
    for _ in 0..2 {
        let response = request(&service, token.expose_secret(), operation.clone()).await?;
        assert_eq!(
            response["error"]["code"], "response_too_large",
            "{response}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}

#[tokio::test]
async fn expired_credential_rejects_even_inspection() -> Result {
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        + 2;
    let token = service.issue_credential("root", expires)?;
    assert_eq!(
        request(&service, token.expose_secret(), json!({"op": "inspect"})).await?["ok"],
        true
    );
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert_eq!(
        request(&service, token.expose_secret(), json!({"op": "inspect"})).await?["error"]["code"],
        "unauthenticated"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn disconnected_worker_does_not_abort_dispatch_and_shutdown_drains_calls() -> Result {
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
    let cap = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let credential = service.issue_credential("root", cap.expires_at)?;
    let socket = dir.path().join("worker.sock");
    let listener = WorkerServer::bind(&socket, service.clone())?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(listener.serve(async {
        let _ = stopped.await;
    }));
    let mut stream = UnixStream::connect(&socket).await?;
    let mut bytes = frame(credential.expose_secret(), invoke("one"));
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    entered.notified().await;
    drop(stream);
    stop.send(()).map_err(|_| "shutdown channel closed")?;
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    release.notify_one();
    task.await??;
    assert!(!socket.exists());
    assert_eq!(
        request(&service, credential.expose_secret(), invoke("one")).await?["result"]["verdict"],
        "allow"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn framing_is_bounded_and_socket_paths_are_not_clobbered() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let cap = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime.clone());
    let credential = service.issue_credential("root", cap.expires_at)?;
    let file = dir.path().join("host-file");
    std::fs::write(&file, "host data")?;
    assert!(WorkerServer::bind(&file, service.clone()).is_err());
    assert_eq!(std::fs::read_to_string(&file)?, "host data");
    let socket = dir.path().join("worker.sock");
    let listener = WorkerServer::bind(&socket, service.clone())?;
    assert_eq!(
        std::fs::metadata(&socket)?.permissions().mode() & 0o777,
        0o600
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(listener.serve(async {
        let _ = stopped.await;
    }));
    for bytes in [
        vec![b'x'; MAX_REQUEST_BYTES],
        frame(credential.expose_secret(), invoke("unterminated")),
    ] {
        let mut stream = UnixStream::connect(&socket).await?;
        stream.write_all(&bytes).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response: Value = serde_json::from_slice(&response)?;
        assert_eq!(response["error"]["code"], "invalid_frame");
    }
    let mut bad_protocol: Value =
        serde_json::from_slice(&frame(credential.expose_secret(), invoke("version")))?;
    bad_protocol["protocol"] = json!("future");
    static OBSERVED_ERRORS: AtomicUsize = AtomicUsize::new(0);
    let observed = service.clone().with_error_observer(|error| {
        assert!(matches!(
            error,
            ProcessError::Invalid("unsupported protocol")
        ));
        OBSERVED_ERRORS.fetch_add(1, Ordering::SeqCst);
    });
    let response: Value = serde_json::from_slice(
        &observed
            .handle_frame(bad_protocol.to_string().as_bytes())
            .await,
    )?;
    assert_eq!(OBSERVED_ERRORS.load(Ordering::SeqCst), 1);
    assert_eq!(
        response,
        json!({"protocol": PROTOCOL, "ok": false,
        "error": {"code": "invalid_request"}})
    );
    assert_eq!(runtime.process("root")?.tree_calls, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop.send(()).map_err(|_| "shutdown channel closed")?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn state_blob_wire_validates_digest_encoding_ownership_and_credentials() -> Result {
    use base64::Engine;
    use chio_core_types::crypto::sha256_hex;
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let cap = root(&runtime, &kernel, 1)?;
    let service = WorkerService::new(runtime.clone());
    let token = service.issue_credential("root", cap.expires_at)?;
    let secret = token.expose_secret();
    let bytes = vec![255; chio_process::MAX_STATE_BLOB_BYTES];
    let sha256 = sha256_hex(&bytes);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let put = json!({"op":"blob_put","sha256":sha256,"data_base64":encoded});
    let result = request(&service, secret, put.clone()).await?;
    assert_eq!(
        result["result"],
        json!({"sha256":sha256,"bytes":bytes.len()})
    );
    let read = json!({"op":"blob_read","sha256":sha256});
    assert_eq!(
        request(&service, secret, read.clone()).await?["result"]["data_base64"],
        encoded
    );
    for bad in [
        json!({"op":"blob_put","sha256":sha256,"data_base64":" /w=="}),
        json!({"op":"blob_put","sha256":sha256_hex(&[255]),"data_base64":"/x=="}),
        json!({"op":"blob_put","sha256":sha256,"data_base64":"AA=="}),
        json!({"op":"blob_read","sha256":sha256,"process_id":"root"}),
        json!({"op":"blob_read","sha256":sha256.to_uppercase()}),
    ] {
        assert_eq!(
            request(&service, secret, bad).await?["error"]["code"],
            "invalid_request"
        );
    }
    assert_eq!(runtime.storage("root")?.tree_blobs, 1);
    assert_eq!(runtime.storage("root")?.tree_bytes, bytes.len() as u64);
    service.revoke_credentials("root")?;
    for operation in [read, put] {
        assert_eq!(
            request(&service, secret, operation).await?["error"]["code"],
            "unauthenticated"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
