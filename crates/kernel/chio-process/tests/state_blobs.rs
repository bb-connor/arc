mod support;

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::{
    ProcessError, ProcessLimits, ProcessRuntime, ProcessStateLimits, MAX_STATE_BLOB_BYTES,
};
use serde_json::{json, Value};
use std::sync::Arc;
use support::{child, kernel, limits, parent_key, root, scope, Result};

struct Server;
#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read".into(), "append".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Ok(Value::Null)
    }
}

#[test]
fn legacy_limits_keep_their_serialized_identity() -> Result {
    let old = json!({"max_processes":100,"max_depth":8,"max_calls":2});
    let decoded: ProcessLimits = serde_json::from_value(old.clone())?;
    assert_eq!(decoded.state, ProcessStateLimits::default());
    assert_eq!(serde_json::to_value(decoded)?, old);
    Ok(())
}

#[tokio::test]
async fn blobs_persist_are_owned_and_detect_corruption() -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), Box::new(Server))?;
    let path = dir.path().join("process.db");
    let runtime = ProcessRuntime::open(&path, kernel.clone())?;
    let parent = root(&runtime, &kernel, 2)?;
    let cap = child(
        &parent,
        &parent_key(),
        "reader",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &cap)?;
    let bytes = [0, 255, 128, 1];
    let reference = runtime.put_blob("root", &bytes)?;
    assert_eq!(reference.sha256, sha256_hex(&bytes));
    assert_eq!(runtime.put_blob("root", &bytes)?, reference);
    assert_eq!(runtime.storage("root")?.tree_blobs, 1);
    assert!(matches!(
        runtime.read_blob("reader", &reference.sha256),
        Err(ProcessError::BlobMissing)
    ));
    runtime.put_blob("reader", &bytes)?;
    assert_eq!(runtime.storage("root")?.tree_bytes, 8);
    drop(runtime);
    let reopened = ProcessRuntime::open(&path, kernel)?;
    assert_eq!(reopened.read_blob("root", &reference.sha256)?, bytes);
    let db = rusqlite::Connection::open(&path)?;
    db.execute(
        "UPDATE process_state_blobs SET data=?1 WHERE process_id='root'",
        [b"oops".as_slice()],
    )?;
    assert!(matches!(
        reopened.read_blob("root", &reference.sha256),
        Err(ProcessError::BlobCorrupt)
    ));
    assert!(matches!(
        reopened.put_blob("root", &bytes),
        Err(ProcessError::BlobCorrupt)
    ));
    reopened.cancel("reader")?;
    assert!(matches!(
        reopened.read_blob("reader", &reference.sha256),
        Err(ProcessError::Cancelled(_))
    ));
    assert!(matches!(
        reopened.put_blob("reader", b"more"),
        Err(ProcessError::Cancelled(_))
    ));
    Ok(())
}

#[tokio::test]
async fn tree_quota_is_atomic_across_connections_and_dedup_survives_full_quota() -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = kernel(dir.path(), Box::new(Server))?;
    let path = dir.path().join("process.db");
    let runtime = ProcessRuntime::open(&path, kernel.clone())?;
    let parent =
        kernel.issue_capability(&parent_key().public_key(), scope(&["read", "append"]), 3600)?;
    let mut quota = limits(2);
    quota.state = ProcessStateLimits {
        max_bytes: 4,
        max_blobs: 2,
    };
    runtime.create_root("root", &parent, quota)?;
    let cap = child(
        &parent,
        &parent_key(),
        "reader",
        &Keypair::generate(),
        scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &cap)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = ["root", "reader"]
        .into_iter()
        .map(|id| {
            let other = ProcessRuntime::open(&path, kernel.clone());
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let other = other?;
                barrier.wait();
                other.put_blob(id, b"1234")
            })
        })
        .collect();
    let mut winner = None;
    for (id, handle) in ["root", "reader"].into_iter().zip(handles) {
        let result = handle.join().map_err(|_| "quota thread panicked")?;
        match result {
            Ok(_) => {
                assert!(winner.is_none());
                winner = Some(id);
            }
            Err(ProcessError::Limit(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let winner = winner.ok_or("no quota winner")?;
    runtime.put_blob(winner, b"1234")?;
    runtime.put_blob(winner, b"")?;
    assert!(matches!(
        runtime.put_blob(if winner == "root" { "reader" } else { "root" }, b""),
        Err(ProcessError::Limit(_))
    ));
    assert_eq!(runtime.storage("reader")?.tree_blobs, 2);
    assert_eq!(runtime.storage("root")?.tree_bytes, 4);
    assert!(runtime.read_blob("root", &"A".repeat(64)).is_err());
    assert!(runtime
        .put_blob("root", &vec![0; MAX_STATE_BLOB_BYTES + 1])
        .is_err());
    Ok(())
}
