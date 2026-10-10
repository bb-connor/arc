//! An output guard rejects the value a committed dispatch actually returned.
//! The rejection happens before the return is recorded, so the operation must
//! terminalize as outcome unknown with a signed denial and no redispatch.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REJECTION: &str = "returned value violates the output policy";

#[derive(Clone, Copy, Debug)]
enum Entry {
    Ordinary,
    Nested,
}

#[derive(Clone, Debug, PartialEq)]
struct Observed {
    output: ToolServerOutput,
    state: Option<AdmissionOperationState>,
    raw_recorded: bool,
    outcome_recorded: bool,
    invocations: u64,
}

struct ReturnedOutputGuard {
    reject: bool,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    observed: Arc<Mutex<Vec<Observed>>>,
}

impl Guard for ReturnedOutputGuard {
    fn name(&self) -> &str {
        "returned-output-guard"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn validate_output_before_release(
        &self,
        _: &GuardContext<'_>,
        output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        let state = self.store.state.lock().map_err(poisoned)?;
        let observed = Observed {
            output: output.clone(),
            state: state.operation.as_ref().map(AdmissionOperationV1::state),
            raw_recorded: state.raw_outcome.is_some(),
            outcome_recorded: state.tool_outcome.is_some(),
            invocations: self.invocations.load(Ordering::SeqCst),
        };
        drop(state);
        self.observed.lock().map_err(poisoned)?.push(observed);
        if self.reject {
            return Err(KernelError::GuardDenied(REJECTION.to_owned()));
        }
        Ok(())
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> KernelError {
    KernelError::Internal("returned output guard state poisoned".into())
}

fn parent(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    entry: Entry,
) -> Result<Option<OperationContext>, KernelError> {
    let Entry::Nested = entry else {
        return Ok(None);
    };
    let session = kernel.open_session(request.agent_id.clone(), Vec::new())?;
    kernel.activate_session(&session)?;
    let parent = make_operation_context(&session, "returned-output-parent", &request.agent_id);
    kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
    Ok(Some(parent))
}

fn evaluate(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    parent: Option<&OperationContext>,
) -> Result<ToolCallResponse, KernelError> {
    match parent {
        None => kernel.evaluate_tool_call_blocking(request),
        Some(parent) => kernel.evaluate_tool_call_with_nested_flow_client_and_security_context(
            parent,
            request,
            &mut NoopNestedFlowClient,
            None,
            None,
        ),
    }
}

struct Case {
    kernel: ChioKernel,
    request: ToolCallRequest,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    observed: Arc<Mutex<Vec<Observed>>>,
}

fn fixture(name: &str, reject: bool) -> Case {
    let (mut kernel, request, store, invocations) = durable_admission_fixture(name);
    let observed = Arc::new(Mutex::new(Vec::new()));
    kernel.add_guard(Box::new(ReturnedOutputGuard {
        reject,
        store: store.clone(),
        invocations: invocations.clone(),
        observed: observed.clone(),
    }));
    Case {
        kernel,
        request,
        store,
        invocations,
        observed,
    }
}

fn returned_value(request: &ToolCallRequest) -> ToolServerOutput {
    ToolServerOutput::Value(serde_json::json!({
        "tool": request.tool_name,
        "echo": request.arguments,
    }))
}

fn at_return_recording(request: &ToolCallRequest) -> Observed {
    Observed {
        output: returned_value(request),
        state: Some(AdmissionOperationState::DispatchCommitted),
        raw_recorded: false,
        outcome_recorded: false,
        invocations: 1,
    }
}

fn observed(observed: &Mutex<Vec<Observed>>) -> Result<Vec<Observed>, KernelError> {
    Ok(observed.lock().map_err(poisoned)?.clone())
}

fn accepted_output_completes(entry: Entry) -> TestResult {
    let Case {
        kernel,
        request,
        store,
        invocations,
        observed: seen,
    } = fixture(&format!("returned-output-accepted-{entry:?}"), false);
    let parent = parent(&kernel, &request, entry)?;
    let response = evaluate(&kernel, &request, parent.as_ref())?;
    assert_eq!(response.verdict, Verdict::Allow, "{entry:?}: {response:?}");
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed(&seen)?,
        [
            at_return_recording(&request),
            Observed {
                output: returned_value(&request),
                state: Some(AdmissionOperationState::Finalizing),
                raw_recorded: true,
                outcome_recorded: true,
                invocations: 1,
            },
        ],
        "{entry:?}"
    );
    Ok(())
}

fn rejected_output_terminalizes_unknown(entry: Entry) -> TestResult {
    let Case {
        kernel,
        request,
        store,
        invocations,
        observed: seen,
    } = fixture(&format!("returned-output-rejected-{entry:?}"), true);

    let parent = parent(&kernel, &request, entry)?;
    let denied = evaluate(&kernel, &request, parent.as_ref())?;

    assert_eq!(
        observed(&seen)?,
        [at_return_recording(&request)],
        "{entry:?}"
    );
    let expected_reason = KernelError::GuardDenied(format!(
        "guard output validation failed: {}",
        KernelError::GuardDenied(REJECTION.to_owned())
    ))
    .to_string();
    assert_eq!(denied.verdict, Verdict::Deny, "{entry:?}: {denied:?}");
    assert_eq!(denied.reason.as_deref(), Some(expected_reason.as_str()));
    assert!(denied.output.is_none());
    assert!(denied.receipt.verify_signature()?);
    assert!(denied.receipt.is_denied());

    let retained = store.operation();
    assert_eq!(
        retained.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(retained.dispatch_commit().is_some());
    {
        let state = store.state.lock().map_err(|_| "admission state poisoned")?;
        assert!(state.raw_outcome.is_none());
        assert!(state.tool_outcome.is_none());
        assert!(state.resolved_output.is_none());
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let usage = store
        .budget
        .get_usage(&request.capability.id, 0)?
        .ok_or("committed quota must remain retained")?;
    assert_eq!(usage.invocation_count, 1);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1, "{entry:?}");
    let logged = receipt_log.get(0).ok_or("returned output denial receipt")?;
    assert_eq!(logged.id, denied.receipt.id);
    assert!(logged.is_denied());
    assert!(logged.verify_signature()?);

    let replay = evaluate(&kernel, &request, parent.as_ref())?;
    assert_eq!(replay.verdict, Verdict::Deny, "{entry:?}: {replay:?}");
    assert!(replay
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("OutcomeUnknownAfterDispatch")));
    assert!(replay.output.is_none());
    assert!(replay.receipt.verify_signature()?);
    assert_eq!(store.operation(), retained);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(observed(&seen)?.len(), 1, "{entry:?}");
    Ok(())
}

#[test]
fn returned_output_guard_accepts_before_recording_on_both_paths() -> TestResult {
    for entry in [Entry::Ordinary, Entry::Nested] {
        accepted_output_completes(entry)?;
    }
    Ok(())
}

#[test]
fn ordinary_returned_output_guard_denial_terminalizes_unknown() -> TestResult {
    rejected_output_terminalizes_unknown(Entry::Ordinary)
}

#[test]
fn nested_returned_output_guard_denial_terminalizes_unknown() -> TestResult {
    rejected_output_terminalizes_unknown(Entry::Nested)
}
