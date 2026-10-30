use super::*;

#[test]
fn stopped_live_return_and_retry_retain_output_until_resume() -> TestResult {
    let (kernel, request, store, invocations) = durable_admission_fixture("stop-live-return");
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        input(&request),
    )?;
    let returned = kernel.record_durable_tool_return(
        &mut admission,
        DurableToolReturnInput {
            request: &request,
            output: &ToolServerOutput::Value(serde_json::json!({"done": true})),
            reported_cost: None,
            context: &context,
            elapsed: Duration::ZERO,
            trusted_now_unix_ms: current_unix_timestamp_ms(),
        },
    )?;
    drop(mutation);
    kernel.emergency_stop("stop live return")?;
    let before = store.operation();
    assert_eq!(before.state(), AdmissionOperationState::Finalizing);
    let result = kernel.finalize_durable_tool_return_with_security_release(
        &mut admission,
        &request,
        &returned,
        None,
    );
    assert!(
        matches!(result, Err(KernelError::OutputWithheld)),
        "{result:?}"
    );
    assert_eq!(store.operation(), before);
    let retried = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(retried, Err(KernelError::OutputWithheld)),
        "{retried:?}"
    );
    assert_eq!(store.operation(), before);
    let planned = kernel.sign_planned_deny_response(
        &request,
        crate::ClientDenialCode::EmergencyStop,
        EMERGENCY_STOP_DENY_REASON,
        None,
    );
    assert!(
        matches!(planned, Err(KernelError::OutputWithheld)),
        "{planned:?}"
    );
    assert_eq!(store.operation(), before);
    kernel.emergency_resume()?;
    let released = kernel.finalize_durable_tool_return_with_security_release(
        &mut admission,
        &request,
        &returned,
        None,
    )?;
    assert_eq!(released.verdict, Verdict::Allow);
    assert!(released.output.is_some());
    assert!(released.receipt.verify_integrity_embedded_key()?);
    assert_eq!(
        released
            .receipt
            .metadata
            .as_ref()
            .ok_or("receipt metadata")?["chio_runtime"]["identity_disposition"],
        "terminal"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn stopped_completed_replay_withholds_without_reinvocation() -> TestResult {
    let (kernel, request, store, invocations) = durable_admission_fixture("stop-completed-replay");
    let original = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(original.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let before = store.operation();
    kernel.emergency_stop("stop completed replay")?;
    let stopped = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(stopped, Err(KernelError::OutputWithheld)),
        "{stopped:?}"
    );
    assert_eq!(store.operation(), before);
    kernel.emergency_resume()?;
    let resumed = kernel.evaluate_tool_call_blocking(&request)?;
    assert_same_receipt(&resumed.receipt, &original.receipt);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
