use super::*;
use chio_process::worker::{InvocationPreparer, PreparationRequest};
use chio_test_support::clock::{scope_unix_secs, unix_seconds, ClockScope};
use std::sync::Mutex;

#[tokio::test]
async fn authority_clock_allows_live_credentials_when_host_time_is_ahead() -> Result {
    let _clock = scope_unix_secs(1_700_000_000);
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let capability = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let token = service.issue_credential("root", capability.expires_at)?;
    let response = request(&service, token.expose_secret(), json!({"op": "inspect"})).await?;
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["result"]["process_id"], "root");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn authority_clock_rejects_expired_issuance_without_persisting_a_credential() -> Result {
    let issued_at = unix_seconds();
    let _clock = scope_unix_secs(issued_at);
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let expiry = issued_at + 600;
    let _expired = scope_unix_secs(expiry);
    assert!(matches!(
        service.issue_credential("root", expiry),
        Err(ProcessError::Invalid(_))
    ));
    let db = rusqlite::Connection::open(dir.path().join("process.db"))?;
    let count: i64 = db.query_row("SELECT count(*) FROM worker_credentials", [], |r| r.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn authority_clock_expiry_blocks_inspection_and_blob_reads_at_the_boundary() -> Result {
    let issued_at = unix_seconds();
    let _clock = scope_unix_secs(issued_at);
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    root(&runtime, &kernel, 2)?;
    let blob = runtime.put_blob("root", b"private process state")?;
    let service = WorkerService::new(runtime);
    let expiry = issued_at + 600;
    let token = service.issue_credential("root", expiry)?;
    let operations = [
        json!({"op": "inspect"}),
        json!({"op": "blob_read", "sha256": blob.sha256}),
    ];
    let _live = scope_unix_secs(expiry - 1);
    for operation in &operations {
        let response = request(&service, token.expose_secret(), operation.clone()).await?;
        assert_eq!(response["ok"], true, "{response}");
    }
    let _expired = scope_unix_secs(expiry);
    for operation in operations {
        let response = request(&service, token.expose_secret(), operation).await?;
        assert_eq!(response["error"]["code"], "unauthenticated", "{response}");
        assert!(response.get("result").is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn authority_clock_failure_denies_issuance_and_stored_state_access() -> Result {
    let issued_at = unix_seconds();
    let _clock = scope_unix_secs(issued_at);
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let capability = root(&runtime, &kernel, 2)?;
    let blob = runtime.put_blob("root", b"private process state")?;
    let service = WorkerService::new(runtime);
    let token = service.issue_credential("root", capability.expires_at)?;
    // The injected clock cannot represent this sample in Unix milliseconds.
    let _failed = scope_unix_secs(u64::MAX);
    assert!(service
        .issue_credential("root", capability.expires_at)
        .is_err());
    for operation in [
        json!({"op": "inspect"}),
        json!({"op": "blob_read", "sha256": blob.sha256}),
    ] {
        let response = request(&service, token.expose_secret(), operation).await?;
        assert_eq!(response["error"]["code"], "runtime_error", "{response}");
        assert!(response.get("result").is_none());
    }
    let db = rusqlite::Connection::open(dir.path().join("process.db"))?;
    let count: i64 = db.query_row("SELECT count(*) FROM worker_credentials", [], |r| r.get(0))?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn authority_clock_authentication_shares_the_kernel_regression_fence() -> Result {
    let issued_at = unix_seconds();
    let _clock = scope_unix_secs(issued_at);
    let dir = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(dir.path(), server(&calls))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    let capability = root(&runtime, &kernel, 2)?;
    let service = WorkerService::new(runtime);
    let token = service.issue_credential("root", capability.expires_at)?;
    let _advanced = scope_unix_secs(issued_at + 10);
    kernel.authority_clock_reading()?;
    let _regressed = scope_unix_secs(issued_at + 9);
    let response = request(&service, token.expose_secret(), json!({"op": "inspect"})).await?;
    assert_eq!(response["error"]["code"], "runtime_error", "{response}");
    assert!(response.get("result").is_none());
    Ok(())
}

struct ChangeClockOnPreparation {
    next_time: u64,
    held_scope: Mutex<Option<ClockScope>>,
    calls: Arc<AtomicUsize>,
}

impl InvocationPreparer for ChangeClockOnPreparation {
    fn prepare(
        &self,
        _: &ProcessRuntime,
        _: PreparationRequest<'_>,
    ) -> std::result::Result<Value, ProcessError> {
        *self
            .held_scope
            .lock()
            .map_err(|_| ProcessError::Configuration("fixture clock lock poisoned"))? =
            Some(scope_unix_secs(self.next_time));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"prepared": "private host output"}))
    }
}

#[tokio::test]
async fn authority_clock_is_rechecked_before_releasing_prepared_output() -> Result {
    for clock_fails in [false, true] {
        let issued_at = unix_seconds();
        let _clock = scope_unix_secs(issued_at);
        let dir = tempfile::tempdir()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let kernel = kernel(dir.path(), server(&calls))?;
        let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
        root(&runtime, &kernel, 2)?;
        let expiry = issued_at + 600;
        let preparations = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(runtime).with_invocation_preparer(Arc::new(
            ChangeClockOnPreparation {
                next_time: if clock_fails { u64::MAX } else { expiry },
                held_scope: Mutex::new(None),
                calls: preparations.clone(),
            },
        ));
        let token = service.issue_credential("root", expiry)?;
        let operation = json!({"op": "prepare_invocation", "operation_key": "prepared", "server_id": "tools", "tool_name": "read", "arguments": {}});
        let response = request(&service, token.expose_secret(), operation).await?;
        assert_eq!(preparations.load(Ordering::SeqCst), 1);
        assert_eq!(
            response["error"]["code"],
            if clock_fails {
                "runtime_error"
            } else {
                "unauthenticated"
            },
            "{response}"
        );
        assert!(response.get("result").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
