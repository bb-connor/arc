//! Cancellation retains request ownership without restoring authorization.
use super::*;
use std::sync::{Condvar, Mutex};
use tokio::sync::Notify;

struct GuardGate {
    entered: StdArc<Notify>,
    release: StdArc<(Mutex<bool>, Condvar)>,
}

impl GuardGate {
    fn install(fixture: &mut Fixture) -> Self {
        // Exercise an actual suspension instead of blocking the Tokio worker.
        fixture.kernel.config.deadlines.always_offload_guards = true;
        let gate = Self {
            entered: StdArc::new(Notify::new()),
            release: StdArc::new((Mutex::new(false), Condvar::new())),
        };
        fixture.kernel.add_guard(Box::new(StalledGuard {
            entered: gate.entered.clone(),
            release: gate.release.clone(),
        }));
        gate
    }
}

impl Drop for GuardGate {
    fn drop(&mut self) {
        *self
            .release
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.release.1.notify_all();
    }
}

struct StalledGuard {
    entered: StdArc<Notify>,
    release: StdArc<(Mutex<bool>, Condvar)>,
}

impl Guard for StalledGuard {
    fn name(&self) -> &str {
        "session-cancellation-gate"
    }

    fn evaluate(&self, _: &GuardContext) -> Result<GuardDecision, KernelError> {
        self.entered.notify_one();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut released = self
            .release
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while !*released {
            let (next, timeout) = self
                .release
                .1
                .wait_timeout(
                    released,
                    deadline.saturating_duration_since(std::time::Instant::now()),
                )
                .unwrap_or_else(|error| error.into_inner());
            released = next;
            if timeout.timed_out() && !*released {
                return Err(KernelError::GuardDenied(
                    "session cancellation fixture guard exceeded its five-second bound".into(),
                ));
            }
        }
        Ok(GuardDecision {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        })
    }
}

fn retained_binding(
    fixture: &Fixture,
    context: &OperationContext,
) -> TestResult<crate::session::PendingThresholdApproval> {
    fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?
        .inflight()
        .get(&context.request_id)
        .and_then(|request| request.pending_threshold_approval.clone())
        .ok_or_else(|| "original threshold claim was not retained".into())
}

async fn drop_at_guard(
    fixture: &Fixture,
    context: &OperationContext,
    gate: &GuardGate,
) -> TestResult {
    let SessionOperation::ToolCall(operation) = operation(&fixture.request) else {
        return Err("tool operation missing".into());
    };
    let mut client = NoopNestedFlowClient;
    let mut evaluation = Box::pin(
        fixture
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client_async(
                context,
                &operation,
                &mut client,
            ),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut evaluation => panic!("evaluation completed before guard gate: {result:?}"),
            () = gate.entered.notified() => {}
        }
    }).await?;
    assert!(fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?
        .inflight()
        .get(&context.request_id)
        .ok_or("active request missing")?
        .pending_threshold_approval
        .is_none());
    drop(evaluation);
    Ok(())
}

#[test]
fn dropped_async_retry_restores_the_original_threshold_claim() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    let original = retained_binding(&fixture, &context)?;
    fixture.approve(proposal)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let gate = GuardGate::install(&mut fixture);
    let result = runtime.block_on(drop_at_guard(&fixture, &context, &gate));
    // Release the real blocking guard before assertions or runtime shutdown.
    drop(gate);
    result?;
    assert_eq!(retained_binding(&fixture, &context)?, original);
    assert_pending_session(&fixture, &context)?;
    // The original durable verifier still determines whether cancellation
    // left a retryable operation or a terminal cancellation receipt.
    evaluate(&fixture, &context, EntryPoint::NestedAsync)?;
    assert!(fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?
        .terminal()
        .get(&context.request_id)
        .is_some());
    Ok(())
}

#[test]
fn dropped_initial_async_request_completes_session_ownership_as_cancelled() -> TestResult {
    let mut fixture = Fixture::new()?;
    let session = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.request.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session)?;
    let context = OperationContext::new(
        session,
        RequestId::new(&fixture.request.request_id),
        fixture.request.agent_id.clone(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let gate = GuardGate::install(&mut fixture);
    let result = runtime.block_on(drop_at_guard(&fixture, &context, &gate));
    drop(gate);
    result?;
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert!(matches!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Cancelled { .. })
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

struct StalledTool {
    server: String,
    tool: String,
    entered: StdArc<Notify>,
    invocations: StdArc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for StalledTool {
    fn server_id(&self) -> &str {
        &self.server
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.tool.clone()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[test]
fn dropped_dispatched_retry_cannot_execute_a_second_effect() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    let original = retained_binding(&fixture, &context)?;
    fixture.approve(proposal)?;
    let entered = StdArc::new(Notify::new());
    fixture.kernel.register_tool_server(Box::new(StalledTool {
        server: fixture.request.server_id.clone(),
        tool: fixture.request.tool_name.clone(),
        entered: entered.clone(),
        invocations: fixture.invocations.clone(),
    }));
    let SessionOperation::ToolCall(operation) = operation(&fixture.request) else {
        return Err("tool operation missing".into());
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        let mut evaluation = Box::pin(fixture.kernel.evaluate_tool_call_operation_with_nested_flow_client_async(&context, &operation, &mut client));
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut evaluation => panic!("evaluation completed before tool gate: {result:?}"),
                () = entered.notified() => {}
            }
        }).await?;
        drop(evaluation);
        TestResult::Ok(())
    })?;
    assert_eq!(retained_binding(&fixture, &context)?, original);
    let response = evaluate(&fixture, &context, EntryPoint::NestedAsync)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
