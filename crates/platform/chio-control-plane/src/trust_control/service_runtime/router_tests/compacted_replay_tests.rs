//! Real RPC reads over a freshly provisioned authority; faults affect only replies.
use super::*;
use crate::durable_admission::{
    payload_maintenance_tests::{
        configured_kernel, raw_payload_present, receipt_operation, request_with_credentials,
    },
    private_tempdir,
};
use crate::{
    DurableAdmissionRuntime, LocalTerminalPayloadMaintenance, TerminalPayloadMaintenanceConfig,
};
use axum::body::{to_bytes, Body};
use axum::http::Request;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use chio_core::{receipt::body::ChioReceipt, SigningAlgorithm};
use chio_kernel::tool_outcome::{ToolOutcomeStore, ToolOutcomeStoreError};
use chio_kernel::{KernelError, ReceiptStoreError, Verdict};
use rusqlite::{Connection, OpenFlags};
use std::error::Error;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Instant;

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone)]
struct ReplyFault {
    mode: Arc<AtomicU8>,
    signer: chio_core::Keypair,
}

async fn fault_reply(
    State(fault): State<ReplyFault>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 4 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let is_receipt = serde_json::from_slice::<AdmissionAuthorityRequest>(&bytes)
        .is_ok_and(|request| request.action == AdmissionAuthorityAction::LoadAdmissionReceipt);
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let mode = fault.mode.load(Ordering::SeqCst);
    if !is_receipt || mode == 0 {
        return response;
    }
    if mode == 1 {
        return Json(AdmissionAuthorityResponse::failure(
            AdmissionAuthorityErrorCode::Fenced,
            "test authority receipt read fenced",
        ))
        .into_response();
    }
    let result = async {
        let body = to_bytes(response.into_body(), 4 * 1024 * 1024).await?;
        let mut envelope: AdmissionAuthorityResponse = serde_json::from_slice(&body)?;
        let result = envelope
            .result
            .as_mut()
            .ok_or_else(|| std::io::Error::other("missing receipt result"))?;
        let mut receipt: ChioReceipt = serde_json::from_value(result.value.clone())?;
        if mode == 2 {
            receipt.algorithm = Some(SigningAlgorithm::Hybrid);
        } else if mode == 6 {
            let other = chio_core::Keypair::generate();
            let mut foreign_body = receipt.body();
            foreign_body.kernel_key = other.public_key();
            receipt.signature = ChioReceipt::sign(foreign_body, &other)?.signature;
        } else {
            let mut body = receipt.body();
            if mode == 3 {
                body.metadata
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("missing metadata"))?
                    [chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY] =
                    serde_json::json!("PRIVATE_PARSER_VALUE_CANARY");
            } else if mode == 4 {
                let other = chio_core::Keypair::generate();
                body.kernel_key = other.public_key();
                receipt = ChioReceipt::sign(body, &other)?;
                result.value = serde_json::to_value(receipt)?;
                return Ok::<_, Box<dyn Error>>(envelope);
            } else if mode == 5 {
                body.metadata
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("missing metadata"))?
                    [chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY]
                    ["operation_id"] = serde_json::json!("a".repeat(64));
            }
            receipt = ChioReceipt::sign(body, &fault.signer)?;
        }
        result.value = serde_json::to_value(receipt)?;
        Ok::<_, Box<dyn Error>>(envelope)
    }
    .await;
    match result {
        Ok(envelope) => Json(envelope).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

struct Host {
    maintenance: Option<LocalTerminalPayloadMaintenance>,
    executor: tokio::runtime::Runtime,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    runtime: DurableAdmissionRuntime,
    fault: Arc<AtomicU8>,
    url: String,
}

impl Host {
    fn open(database: &Path) -> Result<Self, Box<dyn Error>> {
        let runtime =
            DurableAdmissionRuntime::open_with_clock(database, chio_test_support::clock::clock())?;
        let authority = runtime
            .local_authority_store()
            .ok_or("missing local authority")?;
        let mut state = metrics_state("payload-rpc-secret");
        state.budget_store = Some(Arc::new(authority.budget_store()));
        state.revocation_store = Some(Arc::new(authority.revocation_store()));
        state.joint_authority_store = Some(authority);
        let fault = Arc::new(AtomicU8::new(0));
        let router = crate::trust_control::service_runtime::router::build_router(state).layer(
            from_fn_with_state(
                ReplyFault {
                    mode: fault.clone(),
                    signer: runtime.kernel_keypair(),
                },
                fault_reply,
            ),
        );
        let executor = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (url, shutdown, task) = executor.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}", listener.local_addr()?);
            let (shutdown, signal) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = signal.await;
                    })
                    .await
            });
            Ok::<_, std::io::Error>((url, shutdown, task))
        })?;
        Ok(Self {
            maintenance: None,
            executor,
            shutdown: Some(shutdown),
            task: Some(task),
            runtime,
            fault,
            url,
        })
    }
    fn compact(&mut self, database: &Path, digest: &str) -> Result<(), Box<dyn Error>> {
        let config = TerminalPayloadMaintenanceConfig {
            terminal_raw_payload_ttl: Duration::from_secs(10),
            interval: Duration::from_millis(10),
            page_limits: chio_store_sqlite::ToolOutcomeCompactionLimits::default(),
        };
        let owner = LocalTerminalPayloadMaintenance::start(
            self.runtime
                .local_authority_store()
                .ok_or("missing authority")?,
            config,
        )?;
        self.maintenance = Some(owner);
        let deadline = Instant::now() + Duration::from_secs(3);
        while raw_payload_present(database, digest)? && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !raw_payload_present(database, digest)?,
            "actual serving-owner tick did not compact the completed value: {:?}",
            self.maintenance
                .as_ref()
                .map(LocalTerminalPayloadMaintenance::health)
        );
        Ok(())
    }
    fn close(mut self) -> Result<(), Box<dyn Error>> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            self.executor
                .block_on(async { tokio::time::timeout(Duration::from_secs(3), task).await })???;
        }
        if let Some(owner) = self.maintenance.take() {
            assert!(owner.shutdown()?.worker_joined);
        }
        Ok(())
    }
}

fn head(database: &Path) -> Result<i64, Box<dyn Error>> {
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(connection.query_row(
        "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
}

fn replay_fault(mode: u8, expected_code: &str, native: bool) -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("fault-replay.db");
    let mut host = Host::open(&database)?;
    let calls = Arc::new(AtomicU64::new(0));
    let kernel = configured_kernel(&host.runtime, calls.clone())?;
    let request =
        request_with_credentials(&kernel, &host.runtime.kernel_keypair(), "fault-replay")?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let metadata = receipt_operation(&response.receipt)?;
    let outcome = host
        .runtime
        .local_authority_store()
        .ok_or("missing authority")?
        .tool_outcome_store()
        .lookup_by_operation(&metadata.operation_id)?
        .ok_or("missing outcome")?;
    drop(kernel);
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    host.compact(&database, outcome.raw_output_digest().as_str())?;
    let remote = DurableAdmissionRuntime::open_remote(&database, &host.url, "payload-rpc-secret")?;
    let recovered = configured_kernel(&remote, calls.clone())?;
    let before = head(&database)?;
    host.fault.store(mode, Ordering::SeqCst);
    let error = recovered
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("faulted receipt replay must refuse")?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        head(&database)?,
        before,
        "faulted replay must not mutate durable commitments"
    );
    assert_eq!(
        error.report().code,
        expected_code,
        "actual compacted replay error: {error:?}"
    );
    if native {
        assert!(
            error.source().is_some(),
            "native cause was flattened: {error:?}"
        );
    }
    if mode == 1 {
        assert!(matches!(
            error,
            KernelError::ReceiptPersistence(ReceiptStoreError::Fenced)
        ));
    }
    if mode == 3 {
        let mut source = error.source();
        let mut found = false;
        while let Some(cause) = source {
            found |= cause.downcast_ref::<serde_json::Error>().is_some();
            source = cause.source();
        }
        assert!(found, "native serde decode source must remain reachable");
        assert!(!error.to_string().contains("PRIVATE_PARSER_VALUE_CANARY"));
    }
    if mode == 6 {
        let mut source = error.source();
        let mut found = false;
        while let Some(cause) = source {
            found |= cause.downcast_ref::<chio_core::Error>().is_some();
            source = cause.source();
        }
        assert!(
            found,
            "native core signature verification refusal must remain reachable"
        );
    }
    host.fault.store(0, Ordering::SeqCst);
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(head(&database)?, before);
    drop(recovered);
    drop(remote);
    host.close()?;
    Ok(())
}

#[test]
fn compacted_payload_rpc_receipt_fence_preserves_native_store_cause() -> TestResult {
    replay_fault(1, "CHIO-KERNEL-RECEIPT-PERSISTENCE", true)
}
#[test]
fn compacted_payload_rpc_receipt_algorithm_preserves_native_verification_cause() -> TestResult {
    replay_fault(2, "urn:chio:error:attest:receipt-verification-failed", true)
}

#[test]
fn compacted_payload_rpc_receipt_signature_preserves_native_core_cause() -> TestResult {
    replay_fault(6, "urn:chio:error:attest:receipt-verification-failed", true)
}
#[test]
fn compacted_payload_rpc_receipt_metadata_preserves_native_serde_cause() -> TestResult {
    replay_fault(3, "urn:chio:error:attest:signed-json-invalid-shape", true)
}
#[test]
fn compacted_payload_rpc_wrong_signer_and_binding_refuse_without_effects() -> TestResult {
    replay_fault(4, "CHIO-KERNEL-DURABLE-ADMISSION", false)?;
    replay_fault(5, "CHIO-KERNEL-DURABLE-ADMISSION", false)
}

#[test]
fn compacted_payload_rpc_cold_reopen_replays_original_receipt_without_effects() -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("cold-rpc-replay.db");
    let mut host = Host::open(&database)?;
    let calls = Arc::new(AtomicU64::new(0));
    let kernel = configured_kernel(&host.runtime, calls.clone())?;
    let request =
        request_with_credentials(&kernel, &host.runtime.kernel_keypair(), "cold-rpc-replay")?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let metadata = receipt_operation(&response.receipt)?;
    let outcome = host
        .runtime
        .local_authority_store()
        .ok_or("missing authority")?
        .tool_outcome_store()
        .lookup_by_operation(&metadata.operation_id)?
        .ok_or("missing outcome")?;
    let fence = host
        .runtime
        .local_authority_store()
        .ok_or("missing authority")?
        .mutation_fence();
    drop(kernel);
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    host.compact(&database, outcome.raw_output_digest().as_str())?;
    host.close()?;
    let host = Host::open(&database)?;
    let reopened_fence = host
        .runtime
        .local_authority_store()
        .ok_or("missing authority")?
        .mutation_fence();
    assert_eq!(reopened_fence.store_uuid, fence.store_uuid);
    assert!(reopened_fence.owner_epoch > fence.owner_epoch);
    let remote = DurableAdmissionRuntime::open_remote(&database, &host.url, "payload-rpc-secret")?;
    assert!(remote.local_authority_store().is_none());
    let recovered = configured_kernel(&remote, calls.clone())?;
    let ports =
        crate::trust_control::service_runtime::remote_admission::build_remote_admission_stores(
            &host.url,
            "payload-rpc-secret",
            remote.kernel_keypair(),
        )?;
    let raw_error = ports
        .outcomes
        .load_raw_invocation_by_operation(&metadata.operation_id)
        .err()
        .ok_or("compacted RPC read must remain explicit")?;
    assert!(
        matches!(raw_error,ToolOutcomeStoreError::Compacted {raw_output_digest,raw_output_size_bytes} if raw_output_digest == *outcome.raw_output_digest() && raw_output_size_bytes == outcome.to_persisted().raw_output_size_bytes)
    );
    let before = head(&database)?;
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(head(&database)?, before);
    drop(recovered);
    drop(remote);
    host.close()?;
    Ok(())
}
