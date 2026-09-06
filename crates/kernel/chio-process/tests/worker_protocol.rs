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

async fn request(service: &WorkerService, secret: &str, operation: Value) -> Result<Value> {
    Ok(serde_json::from_slice(
        &service.handle_frame(&frame(secret, operation)).await,
    )?)
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
    assert_eq!(
        request(&service, secret, invoke("after-cancel")).await?["error"]["code"],
        "cancelled"
    );
    assert_eq!(
        runtime.process("root")?.state,
        chio_process::ProcessState::Running
    );
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
    let response: Value = serde_json::from_slice(
        &service
            .handle_frame(bad_protocol.to_string().as_bytes())
            .await,
    )?;
    assert_eq!(response["error"]["code"], "invalid_request");
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
