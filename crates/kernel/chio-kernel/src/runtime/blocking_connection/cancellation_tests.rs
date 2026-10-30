use super::*;
use crate::{ChioKernel, KernelConfig, ToolCallRequest, Verdict};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::provider_attempt::ProviderAttemptBindingV1;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::task::Poll;
use std::time::Duration;
use tokio::sync::oneshot;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const FUSE: Duration = Duration::from_secs(5);
const NOW: u64 = 1_800_000_001;

#[derive(Default)]
struct Probe {
    started: AtomicUsize,
    completed: AtomicUsize,
    threads: Mutex<Vec<std::thread::ThreadId>>,
    contexts: Mutex<Vec<ToolInvocationContext>>,
    start_signal: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl Probe {
    fn work(
        &self,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.threads
            .lock()
            .map_err(|_| fixture_error("thread observations poisoned"))?
            .push(std::thread::current().id());
        if let Some(signal) = self
            .start_signal
            .lock()
            .map_err(|_| fixture_error("start signal poisoned"))?
            .take()
        {
            let _ = signal.send(());
        }
        if let Some(release) = self
            .release
            .lock()
            .map_err(|_| fixture_error("release gate poisoned"))?
            .as_ref()
        {
            release
                .recv_timeout(FUSE)
                .map_err(|error| fixture_error(&format!("callback release failed: {error}")))?;
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"done": true, "tool": tool, "arguments": arguments}))
    }

    fn gated() -> (Arc<Self>, oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (start_signal, started) = oneshot::channel();
        let (release, receiver) = mpsc::channel();
        (
            Arc::new(Self {
                start_signal: Mutex::new(Some(start_signal)),
                release: Mutex::new(Some(receiver)),
                ..Self::default()
            }),
            started,
            release,
        )
    }
}

fn fixture_error(reason: &str) -> KernelError {
    KernelError::ToolServerError(reason.to_owned())
}

impl BlockingToolServerConnection for Probe {
    fn server_id(&self) -> &str {
        "blocking-adapter"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["work".into()]
    }

    fn invoke_blocking(
        &self,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        self.work(tool, arguments)
    }

    fn invoke_blocking_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        self.contexts
            .lock()
            .map_err(|_| fixture_error("context observations poisoned"))?
            .push(context.clone());
        self.work(context.tool_name(), arguments)
    }

    fn invoke_blocking_in_context(
        &self,
        context: &ToolDispatchContext,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(context.request_id(), "adapter-request");
        assert_eq!(context.attempt_id(), "adapter-attempt");
        self.work(tool, arguments)
    }

    fn prepare_delivery_blocking(&self, context: &ToolDispatchContext) -> Result<(), KernelError> {
        assert_eq!(context.request_id(), "adapter-request");
        self.work("prepare", serde_json::Value::Null).map(|_| ())
    }
}

struct PoolBlocker {
    release: Option<mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), mpsc::RecvTimeoutError>>>,
}

impl Drop for PoolBlocker {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl PoolBlocker {
    async fn occupy() -> TestResult<Self> {
        let (started, receive_started) = oneshot::channel();
        let (release, receiver) = mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            receiver.recv_timeout(FUSE)
        });
        let blocker = Self {
            release: Some(release),
            task: Some(task),
        };
        tokio::time::timeout(FUSE, receive_started).await??;
        Ok(blocker)
    }

    async fn release_and_drain(mut self) -> TestResult {
        self.release
            .take()
            .ok_or("blocking pool release missing")?
            .send(())?;
        self.task
            .take()
            .ok_or("blocking pool task missing")?
            .await??;
        drain_pool().await
    }
}

async fn drain_pool() -> TestResult {
    // One blocking slot and FIFO work make this sentinel complete only after
    // every preceding queued callback has either run or been cancelled.
    tokio::time::timeout(FUSE, tokio::task::spawn_blocking(|| ())).await??;
    Ok(())
}

fn current_thread_runtime() -> TestResult<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()?)
}

fn request() -> TestResult<ToolCallRequest> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "adapter-capability".into(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "blocking-adapter".into(),
                    tool_name: "work".into(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: NOW - 1,
            expires_at: NOW + 300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    Ok(ToolCallRequest {
        request_id: "adapter-request".into(),
        capability: capability.clone(),
        tool_name: "work".into(),
        server_id: "blocking-adapter".into(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"record": "R2-007"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })
}

fn dispatch_context() -> TestResult<ToolDispatchContext> {
    let attempt = ProviderAttemptBindingV1 {
        operation_id: "a".repeat(64),
        attempt_id: "adapter-attempt".into(),
        transport_id: "adapter-transport".into(),
        transport_key_epoch: 1,
    };
    attempt.validate()?;
    Ok(ToolDispatchContext::new("adapter-request", attempt))
}

enum Route {
    Invoke,
    Caller,
    CallerCost,
    Dispatch,
    DispatchCost,
    Prepare,
}

fn invocation<'a>(
    route: Route,
    adapter: &'a BlockingToolServerAdapter,
    caller: &'a ToolInvocationContext,
    dispatch: &'a ToolDispatchContext,
) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, KernelError>> + Send + 'a>> {
    let args = serde_json::json!({"record": "R2-007"});
    match route {
        Route::Invoke => adapter.invoke("work", args, None),
        Route::Caller => adapter.invoke_with_context(caller, args, None),
        Route::CallerCost => Box::pin(async move {
            adapter
                .invoke_with_cost_and_context(caller, args, None)
                .await
                .map(|(value, _)| value)
        }),
        Route::Dispatch => adapter.invoke_in_context(dispatch, "work", args, None),
        Route::DispatchCost => Box::pin(async move {
            adapter
                .invoke_with_cost_in_context(dispatch, "work", args, None)
                .await
                .map(|(value, _)| value)
        }),
        Route::Prepare => Box::pin(async move {
            adapter
                .prepare_delivery(dispatch)
                .await
                .map(|()| serde_json::Value::Null)
        }),
    }
}

fn queued_cancellation(route: Route, deadline: bool) -> TestResult {
    let probe = Arc::new(Probe::default());
    let adapter = BlockingToolServerAdapter::new(probe.clone())?;
    let caller = ToolInvocationContext::from_request(&request()?)?;
    let dispatch = dispatch_context()?;
    let runtime = current_thread_runtime()?;
    runtime.block_on(async {
        let blocker = PoolBlocker::occupy().await?;
        let mut call = invocation(route, &adapter, &caller, &dispatch);
        poll_fn(|cx| {
            assert!(matches!(call.as_mut().poll(cx), Poll::Pending), "occupied blocking pool must queue the adapter callback");
            Poll::Ready(())
        }).await;
        assert_eq!(probe.started.load(Ordering::SeqCst), 0);
        if deadline {
            match tokio::time::timeout(Duration::ZERO, call).await {
                Ok(result) => return Err(format!("queued call completed before its deadline: {result:?}").into()),
                Err(elapsed) => assert_eq!(elapsed.to_string(), "deadline has elapsed"),
            }
        } else {
            drop(call);
        }
        blocker.release_and_drain().await?;
        assert_eq!(probe.started.load(Ordering::SeqCst), 0, "cancelled queued adapter work must never enter the blocking callback after its caller returns");
        assert_eq!(probe.completed.load(Ordering::SeqCst), 0);
        Ok(())
    })
}

#[test]
fn cancelled_queued_invoke_never_starts() -> TestResult {
    queued_cancellation(Route::Invoke, false)
}

#[test]
fn cancelled_queued_caller_context_never_starts() -> TestResult {
    queued_cancellation(Route::Caller, false)
}

#[test]
fn cancelled_queued_caller_cost_never_starts() -> TestResult {
    queued_cancellation(Route::CallerCost, false)
}

#[test]
fn cancelled_queued_dispatch_context_never_starts() -> TestResult {
    queued_cancellation(Route::Dispatch, false)
}

#[test]
fn cancelled_queued_dispatch_cost_never_starts() -> TestResult {
    queued_cancellation(Route::DispatchCost, false)
}

#[test]
fn cancelled_queued_preparation_never_starts() -> TestResult {
    queued_cancellation(Route::Prepare, false)
}

#[test]
fn expired_queued_caller_context_never_starts() -> TestResult {
    queued_cancellation(Route::Caller, true)
}

#[test]
fn adapter_keeps_async_worker_responsive_while_started_callback_waits() -> TestResult {
    let (probe, started, release) = Probe::gated();
    let adapter = Arc::new(BlockingToolServerAdapter::new(probe.clone())?);
    let executor_thread = std::thread::current().id();
    let runtime = current_thread_runtime()?;
    runtime.block_on(async {
        let task =
            tokio::spawn(async move { adapter.invoke("work", serde_json::json!({}), None).await });
        tokio::time::timeout(FUSE, started).await??;
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        assert_eq!(probe.completed.load(Ordering::SeqCst), 0);
        release.send(())?;
        assert_eq!(
            task.await??,
            serde_json::json!({"done": true, "tool": "work", "arguments": {}})
        );
        assert_eq!(probe.completed.load(Ordering::SeqCst), 1);
        assert_ne!(
            probe
                .threads
                .lock()
                .map_err(|_| "thread observations poisoned")?
                .first(),
            Some(&executor_thread)
        );
        Ok(())
    })
}

#[test]
fn cancelling_started_adapter_work_does_not_claim_it_never_executed() -> TestResult {
    let (probe, started, release) = Probe::gated();
    let adapter = Arc::new(BlockingToolServerAdapter::new(probe.clone())?);
    let runtime = current_thread_runtime()?;
    runtime.block_on(async {
        let task =
            tokio::spawn(async move { adapter.invoke("work", serde_json::json!({}), None).await });
        tokio::time::timeout(FUSE, started).await??;
        task.abort();
        let error = task
            .await
            .err()
            .ok_or("cancelled caller unexpectedly completed")?;
        assert!(error.is_cancelled(), "{error:?}");
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        assert_eq!(probe.completed.load(Ordering::SeqCst), 0);
        release.send(())?;
        drain_pool().await?;
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe.completed.load(Ordering::SeqCst),
            1,
            "already-started synchronous work remains running after caller cancellation"
        );
        Ok(())
    })
}

#[test]
fn adapter_without_runtime_preserves_synchronous_execution() -> TestResult {
    let probe = Arc::new(Probe::default());
    let adapter = BlockingToolServerAdapter::new(probe.clone())?;
    let result = futures::executor::block_on(adapter.invoke("work", serde_json::json!({}), None))?;
    assert_eq!(
        result,
        serde_json::json!({"done": true, "tool": "work", "arguments": {}})
    );
    assert_eq!(probe.started.load(Ordering::SeqCst), 1);
    assert_eq!(probe.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        probe
            .threads
            .lock()
            .map_err(|_| "thread observations poisoned")?
            .as_slice(),
        &[std::thread::current().id()]
    );
    Ok(())
}

#[test]
fn healthy_adapter_through_kernel_completes_with_one_blocking_slot() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW);
    let request = request()?;
    let probe = Arc::new(Probe::default());
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![request.capability.issuer.clone()],
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"R2-007-adapter-test"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: crate::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: crate::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: crate::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: crate::MemoryBudgetConfig::defaults(),
            deadlines: crate::HotPathDeadlineConfig {
                dispatch_budget_ms: 500,
                ..crate::HotPathDeadlineConfig::default()
            },
        },
        chio_test_support::clock::clock(),
    );
    kernel.register_tool_server(Box::new(BlockingToolServerAdapter::new(probe.clone())?));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()?;
    let response = runtime.block_on(kernel.evaluate_tool_call(&request))?;
    runtime.block_on(drain_pool())?;
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "{:?} {:?}",
        response.reason,
        response.receipt.metadata
    );
    assert_eq!(
        response.output,
        Some(crate::ToolCallOutput::Value(
            serde_json::json!({"done": true, "tool": "work", "arguments": {"record": "R2-007"}})
        ))
    );
    assert_eq!(probe.started.load(Ordering::SeqCst), 1);
    assert_eq!(probe.completed.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_integrity_embedded_key()?);
    let contexts = probe
        .contexts
        .lock()
        .map_err(|_| "context observations poisoned")?;
    assert_eq!(contexts.len(), 1);
    let context = contexts
        .first()
        .ok_or("kernel invocation context missing")?;
    assert_eq!(context.request_id(), request.request_id);
    assert_eq!(context.capability_id(), request.capability.id);
    assert_eq!(context.subject_key(), request.agent_id);
    assert_eq!(
        context.capability_hash(),
        sha256_hex(&canonical_json_bytes(&request.capability)?)
    );
    Ok(())
}

#[test]
fn expired_worker_refuses_before_entering_the_blocking_callback() -> TestResult {
    let probe = Arc::new(Probe::default());
    let adapter = BlockingToolServerAdapter::new(probe.clone())?;
    let runtime = current_thread_runtime()?;
    runtime.block_on(async {
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            with_blocking_tool_dispatch(
                Some(tokio::time::Instant::now()),
                Duration::from_millis(500),
                || handle.block_on(adapter.invoke("work", serde_json::json!({}), None)),
            )
        })
        .await?;
        let error = match result {
            Ok(value) => return Err(format!("expired callback ran: {value:?}").into()),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                KernelError::HotPathDeadlineExceeded {
                    stage: crate::HotPathStage::Dispatch,
                    budget_ms: 500,
                }
            ),
            "{error:?}"
        );
        drain_pool().await?;
        assert_eq!(probe.started.load(Ordering::SeqCst), 0);
        assert_eq!(probe.completed.load(Ordering::SeqCst), 0);
        Ok(())
    })
}

#[test]
fn worker_inline_opportunity_is_single_use_and_later_calls_queue() -> TestResult {
    let probe = Arc::new(Probe::default());
    let adapter = BlockingToolServerAdapter::new(probe.clone())?;
    let runtime = current_thread_runtime()?;
    runtime.block_on(async {
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            with_blocking_tool_dispatch(Some(tokio::time::Instant::now() + FUSE), FUSE, || {
                handle.block_on(async {
                    assert_eq!(
                        adapter.invoke("work", serde_json::json!({"first": true}), None).await?,
                        serde_json::json!({"done": true, "tool": "work", "arguments": {"first": true}})
                    );
                    let mut later = adapter.invoke("work", serde_json::json!({"later": true}), None);
                    poll_fn(|cx| {
                        assert!(matches!(later.as_mut().poll(cx), Poll::Pending), "only the first adapter call may reuse the physical worker");
                        Poll::Ready(())
                    }).await;
                    drop(later);
                    Ok::<(), KernelError>(())
                })
            })
        }).await??;
        drain_pool().await?;
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        assert_eq!(probe.completed.load(Ordering::SeqCst), 1);
        Ok(())
    })
}

#[test]
fn worker_scope_restores_prior_context_after_nesting_and_unwind() -> TestResult {
    let probe = Arc::new(Probe::default());
    let adapter = BlockingToolServerAdapter::new(probe.clone())?;
    let runtime = current_thread_runtime()?;
    runtime.block_on(async {
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            with_blocking_tool_dispatch(Some(tokio::time::Instant::now() + FUSE), FUSE, || {
                let unwound = std::panic::catch_unwind(|| {
                    with_blocking_tool_dispatch(
                        Some(tokio::time::Instant::now()),
                        Duration::from_millis(1),
                        || panic!("worker scope unwind control"),
                    )
                });
                let payload = match unwound {
                    Ok(()) => return Err(fixture_error("nested scope did not unwind")),
                    Err(payload) => payload,
                };
                assert_eq!(
                    payload.downcast_ref::<&str>(),
                    Some(&"worker scope unwind control")
                );
                handle.block_on(async {
                    assert_eq!(
                        adapter.invoke("work", serde_json::json!({}), None).await?,
                        serde_json::json!({"done": true, "tool": "work", "arguments": {}})
                    );
                    Ok::<(), KernelError>(())
                })
            })?;
            // The raw worker no longer carries the restored outer context.
            handle.block_on(async {
                let mut call = adapter.invoke("work", serde_json::json!({}), None);
                poll_fn(|cx| {
                    assert!(
                        matches!(call.as_mut().poll(cx), Poll::Pending),
                        "worker context must not leak into the next unscoped call"
                    );
                    Poll::Ready(())
                })
                .await;
                drop(call);
                Ok::<(), KernelError>(())
            })
        })
        .await??;
        drain_pool().await?;
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        assert_eq!(probe.completed.load(Ordering::SeqCst), 1);
        Ok(())
    })
}
