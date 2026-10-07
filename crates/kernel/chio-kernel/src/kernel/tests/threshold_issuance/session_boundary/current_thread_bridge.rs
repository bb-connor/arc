//! A sync entrypoint refused on a current-thread runtime keeps the approved wait.

use super::*;

/// Trusted context authority that parks the first tool evaluation after the
/// retry claim, immediately before the sync dispatch bridge, and records which
/// Tokio runtime flavor the bridge is about to see.
struct BridgeProbe {
    checkpoint: StdArc<Checkpoint>,
    runtimes: Mutex<Vec<&'static str>>,
}

impl BridgeProbe {
    fn runtimes(&self) -> TestResult<Vec<&'static str>> {
        Ok(self
            .runtimes
            .lock()
            .map_err(|_| "probe runtime log poisoned")?
            .clone())
    }
}

fn current_runtime() -> &'static str {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::CurrentThread) => "current-thread",
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => "multi-thread",
        Ok(_) => "other",
        Err(_) => "none",
    }
}

fn internal(error: impl std::fmt::Display) -> KernelError {
    KernelError::Internal(error.to_string())
}

impl SecurityInvocationContextAuthority for BridgeProbe {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        self.runtimes
            .lock()
            .map_err(|_| internal("probe runtime log poisoned"))?
            .push(current_runtime());
        self.checkpoint.hold().map_err(internal)?;
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new("tenant-bridge-probe")
                    .map_err(internal)?,
                chio_security_types::ports::SessionId::new(context.session_id.as_str())
                    .map_err(internal)?,
                chio_security_types::PrincipalId::new(context.agent_id.as_str())
                    .map_err(internal)?,
                chio_security_types::ports::IsolationEpochId::new("isolation-bridge-probe")
                    .map_err(internal)?,
                chio_security_types::ports::LineageId::new(operation.capability.id.as_str())
                    .map_err(internal)?,
                1,
            ),
        ))
    }
}

fn evaluate_exact(
    fixture: &Fixture,
    context: &OperationContext,
    entry: EntryPoint,
) -> Result<ToolCallResponse, KernelError> {
    evaluate(fixture, context, entry).map_err(|error| match error.downcast::<KernelError>() {
        Ok(error) => *error,
        Err(error) => internal(error),
    })
}

fn summary(result: &Result<ToolCallResponse, KernelError>) -> String {
    match result {
        Ok(response) => format!("Ok({:?} {:?})", response.verdict, response.reason),
        Err(error) => format!("Err({error:?})"),
    }
}

/// Retry the approved wait through the same sync entrypoint on a multi-thread
/// runtime, where the bridge is supported.
fn retry_on_multi_thread_runtime(
    fixture: &Fixture,
    context: &OperationContext,
    entry: EntryPoint,
) -> TestResult<Result<ToolCallResponse, KernelError>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    Ok(runtime.block_on(async { evaluate_exact(fixture, context, entry) }))
}

fn assert_completed_once(
    fixture: &Fixture,
    context: &OperationContext,
    entry: EntryPoint,
    retried: Result<ToolCallResponse, KernelError>,
) -> TestResult {
    let response = retried?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(response.terminal_state, OperationTerminalState::Completed);
    assert_eq!(
        RequestState::read(fixture, context)?,
        RequestState::finished(OperationTerminalState::Completed, 1)
    );
    let replay = retry_on_multi_thread_runtime(fixture, context, entry)?;
    assert!(
        matches!(
            &replay,
            Err(KernelError::Session(
                crate::session::SessionError::DuplicateRequestLineage { request_id }
            )) if request_id == &context.request_id
        ),
        "{}",
        summary(&replay)
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

fn refused_bridge_keeps_approved_wait(entry: EntryPoint) -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session_using(&fixture, entry)?;
    fixture.approve(proposal)?;
    let pending = RequestState::read(&fixture, &context)?;
    let original = pending
        .threshold_binding
        .clone()
        .ok_or("original threshold binding missing")?;
    assert_eq!(
        pending,
        RequestState {
            threshold_binding: Some(original),
            ..RequestState::claimed()
        }
    );

    let (checkpoint, control) = checkpoint();
    let probe = StdArc::new(BridgeProbe {
        checkpoint,
        runtimes: Mutex::new(Vec::new()),
    });
    fixture
        .kernel
        .set_security_invocation_context_authority(probe.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let refused = {
        let fixture = &fixture;
        let context = &context;
        std::thread::scope(
            |scope| -> TestResult<Result<ToolCallResponse, KernelError>> {
                let call = scope.spawn(move || {
                    runtime.block_on(async { evaluate_exact(fixture, context, entry) })
                });
                control.entered.recv_timeout(HOLD_TIMEOUT)?;
                assert_eq!(
                    RequestState::read(fixture, context)?,
                    RequestState::claimed()
                );
                assert_eq!(probe.runtimes()?, vec!["current-thread"]);
                control.release.send(())?;
                Ok(call.join().map_err(|_| "bridge call panicked")?)
            },
        )?
    };
    fixture.kernel.security_invocation_context_authority = None;

    assert!(
        matches!(
            &refused,
            Err(KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime)
        ),
        "{}",
        summary(&refused)
    );
    assert_eq!(probe.runtimes()?, vec!["current-thread"]);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    let after_refusal = RequestState::read(&fixture, &context)?;
    let retried = retry_on_multi_thread_runtime(&fixture, &context, entry)?;
    assert!(
        matches!(&retried, Ok(response) if response.verdict == Verdict::Allow),
        "approved wait after the bridge refusal: retry {}, state after refusal {after_refusal:?}",
        summary(&retried)
    );
    assert_eq!(after_refusal, pending);
    assert_completed_once(&fixture, &context, entry, retried)
}

fn approved_wait_on_multi_thread_runtime(entry: EntryPoint) -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session_using(&fixture, entry)?;
    fixture.approve(proposal)?;
    let retried = retry_on_multi_thread_runtime(&fixture, &context, entry)?;
    assert_completed_once(&fixture, &context, entry, retried)
}

#[test]
fn session_sync_bridge_refusal_keeps_approved_threshold_wait() -> TestResult {
    refused_bridge_keeps_approved_wait(EntryPoint::Session)
}

#[test]
fn nested_sync_bridge_refusal_keeps_approved_threshold_wait() -> TestResult {
    refused_bridge_keeps_approved_wait(EntryPoint::NestedSync)
}

#[test]
fn session_approved_threshold_wait_completes_on_multi_thread_runtime() -> TestResult {
    approved_wait_on_multi_thread_runtime(EntryPoint::Session)
}

#[test]
fn nested_sync_approved_threshold_wait_completes_on_multi_thread_runtime() -> TestResult {
    approved_wait_on_multi_thread_runtime(EntryPoint::NestedSync)
}
