use super::*;
use crate::admission_operation::I_JSON_MAX_SAFE_INTEGER;

#[path = "return_signing.rs"]
mod signing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn substitute_captured_participant(
    operation: AdmissionOperationV1,
) -> Result<AdmissionOperationV1, AdmissionCaptureError> {
    let map = |error: serde_json::Error| AdmissionCaptureError::Invariant(error.to_string());
    let mut persisted = operation.to_persisted();
    let mut attachments = operation.attachments().to_vec();
    attachments.push(AdmissionAttachment::GovernedApprovalLedgerDigest(
        crate::admission_operation::AdmissionDigest::try_new("substituted_ledger", "a".repeat(64))
            .map_err(AdmissionCaptureError::Operation)?,
    ));
    persisted.attachments =
        serde_json::from_value(serde_json::to_value(attachments).map_err(map)?).map_err(map)?;
    AdmissionOperationV1::from_persisted(persisted).map_err(AdmissionCaptureError::Operation)
}

#[test]
fn changed_capture_participant_denies_before_tool_effect_and_retains_accounting() -> TestResult {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("changed-capture-participant");
    store
        .substitute_capture_participant
        .store(true, Ordering::SeqCst);
    if let Ok(response) = kernel.evaluate_tool_call_blocking(&request) {
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
    }
    assert!(!store.substitute_capture_participant.load(Ordering::SeqCst));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let operation = store.operation();
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.governed_approval_ledger_digest().is_none());
    assert!(store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome
        .is_none());
    let usage = store
        .budget
        .get_usage(&request.capability.id, 0)?
        .ok_or("captured usage")?;
    assert_eq!(
        usage.invocation_count, 1,
        "unconfirmed capture cannot be refunded"
    );
    Ok(())
}

fn ordinary_return_context_has_no_caller_artifact_limit(nested: bool) -> TestResult {
    let (kernel, mut request, store, invocations) =
        durable_admission_fixture("ordinary-frozen-return-context");
    request.arguments["payload"] = serde_json::Value::String("x".repeat(262_145));
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    assert!(
        crate::admission_operation::RetainedToolAdmissionRequestV1::from_admission(
            &request,
            &matching,
            &[],
            None,
        )
        .is_err(),
        "caller storage must keep its original artifact bound"
    );
    let response = if nested {
        let session = kernel.open_session("context-parent".into(), Vec::new())?;
        kernel.activate_session(&session)?;
        let parent = make_operation_context(&session, "parent-request", "context-parent");
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )?
    } else {
        kernel.evaluate_tool_call_blocking(&request)?
    };
    assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert!(store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome
        .is_some());
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

#[test]
fn ordinary_return_context_preserves_large_request_behavior() -> TestResult {
    ordinary_return_context_has_no_caller_artifact_limit(false)
}

#[test]
fn nested_return_context_preserves_large_request_behavior() -> TestResult {
    ordinary_return_context_has_no_caller_artifact_limit(true)
}

fn pending_admission(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
) -> Result<(DurableToolAdmission, PreExecutionBudgetMutation), KernelError> {
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .map_err(|error| KernelError::Internal(error.to_string()))?;
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(request, &matching, now)?
        .ok_or_else(|| KernelError::Internal("test requires durable admission".into()))?;
    let (_, mutation) = kernel
        .check_and_increment_budget(
            request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    kernel.mark_durable_capture_pending(&mut admission, now)?;
    Ok((admission, mutation))
}

fn input(request: &ToolCallRequest) -> DurableToolReturnContextInput<'_> {
    DurableToolReturnContextInput {
        request,
        matched_grant_index: 0,
        extra_receipt_metadata: Some(serde_json::json!({"admitted_value": "original"})),
        pre_invocation_guard_evidence: &[],
        verified_payee_binding: None,
        verified_purchase: None,
        verified_recovery: None,
        trusted_now_unix_ms: current_unix_timestamp_ms(),
        security_invocation_context: None,
        security_release_required: false,
    }
}

#[test]
fn capture_callback_panics_retain_uncertainty_without_poisoning_recovery() -> TestResult {
    for boundary in [1, 2] {
        let (kernel, request, store, invocations) = durable_admission_fixture("capture-panic");
        let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
        store
            .panic_capture_boundary
            .store(boundary, Ordering::SeqCst);
        let result = kernel.freeze_and_commit_durable_dispatch(
            &mut admission,
            &request.capability,
            &mut mutation,
            input(&request),
        );
        assert!(matches!(
            result,
            Err(DurableDispatchCommitError::CommitUnconfirmed(_))
        ));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        // A panic must not unwind through the mutation sequencer. Recovery
        // reads the actual operation rather than assuming the write failed.
        drop(admission);
        let _clock =
            crate::scope_fixed_runtime_for_current_thread(current_unix_timestamp() + 61, []);
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
        assert_eq!(
            store.operation().state(),
            if boundary == 1 {
                AdmissionOperationState::CompensatedBeforeDispatch
            } else {
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            }
        );
        let usage = store
            .budget
            .get_usage(&request.capability.id, 0)?
            .ok_or("budget usage")?;
        assert_eq!(usage.invocation_count, u32::from(boundary == 2));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn invalid_return_context_cannot_commit_dispatch_or_capture_budget() -> TestResult {
    let (mut kernel, request, store, invocations) = durable_admission_fixture("invalid-context");
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let before = store.operation();
    kernel.config.memory_budget.max_stream_chunks = I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(kernel
        .freeze_and_commit_durable_dispatch(
            &mut admission,
            &request.capability,
            &mut mutation,
            input(&request),
        )
        .is_err());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(store.operation(), before);
    assert!(store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome
        .is_none());
    Ok(())
}

#[test]
fn return_context_rejects_request_or_grant_substitution_before_commit() -> TestResult {
    let (kernel, request, store, _) = durable_admission_fixture("substituted-context");
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let before = store.operation();
    let mut changed_arguments = request.clone();
    changed_arguments.arguments["record"] = serde_json::json!("another");
    let mut changed_capability = request.clone();
    changed_capability.capability.id.push_str("-another");
    let mut changed_id = request.clone();
    changed_id.request_id.push_str("-another");
    for candidate in [&changed_arguments, &changed_capability, &changed_id] {
        assert!(kernel
            .freeze_and_commit_durable_dispatch(
                &mut admission,
                &candidate.capability,
                &mut mutation,
                input(candidate),
            )
            .is_err());
        assert_eq!(store.operation(), before);
    }
    let mut wrong_grant = input(&request);
    wrong_grant.matched_grant_index = usize::MAX;
    assert!(kernel
        .freeze_and_commit_durable_dispatch(
            &mut admission,
            &request.capability,
            &mut mutation,
            wrong_grant,
        )
        .is_err());
    assert_eq!(store.operation(), before);
    Ok(())
}

#[test]
fn frozen_return_context_keeps_limits_and_metadata_when_kernel_configuration_changes() -> TestResult
{
    let (mut kernel, request, store, _) = durable_admission_fixture("frozen-return-material");
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_durable_tool_return_context(&admission, input(&request))?;
    let limit = kernel.config.memory_budget.max_stream_chunks;
    kernel.config.memory_budget.max_stream_chunks = I_JSON_MAX_SAFE_INTEGER + 1;
    kernel.capture_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        None,
        current_unix_timestamp_ms(),
    )?;
    assert!(
        kernel
            .freeze_durable_tool_return_context(&admission, input(&request))
            .is_err(),
        "context cannot be manufactured after dispatch commitment"
    );
    kernel.record_durable_tool_return(
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
    let state = store.state.lock().map_err(|_| "test lock")?;
    let raw = state.raw_outcome.as_ref().ok_or("missing raw outcome")?;
    assert_eq!(raw.stream_limits().max_chunks, limit);
    assert_eq!(
        raw.receipt_metadata_snapshot().ok_or("missing metadata")?["admitted_value"],
        "original"
    );
    Ok(())
}

#[test]
fn frozen_return_context_rejects_substituted_return_request_before_persistence() -> TestResult {
    let (kernel, request, store, _) = durable_admission_fixture("frozen-request-binding");
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        input(&request),
    )?;
    let mut substituted = request.clone();
    substituted.arguments = serde_json::json!({"record": "another"});
    let result = kernel.record_durable_tool_return(
        &mut admission,
        DurableToolReturnInput {
            request: &substituted,
            output: &ToolServerOutput::Value(serde_json::json!({"done": true})),
            reported_cost: None,
            context: &context,
            elapsed: Duration::ZERO,
            trusted_now_unix_ms: current_unix_timestamp_ms(),
        },
    );
    assert!(result
        .as_ref()
        .is_err_and(|error| error.to_string().contains("request differs")));
    assert!(store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome
        .is_none());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    Ok(())
}

#[test]
fn frozen_return_context_cannot_cross_operations_with_the_same_request_id() -> TestResult {
    let (kernel, request, _, _) = durable_admission_fixture("shared-request-id");
    let (admission, _) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_durable_tool_return_context(&admission, input(&request))?;
    let (other_kernel, other_request, other_store, _) =
        durable_admission_fixture("shared-request-id");
    let (mut other_admission, mut mutation) = pending_admission(&other_kernel, &other_request)?;
    other_kernel.capture_and_commit_durable_dispatch(
        &mut other_admission,
        &other_request.capability,
        &mut mutation,
        None,
        current_unix_timestamp_ms(),
    )?;
    let result = other_kernel.record_durable_tool_return(
        &mut other_admission,
        DurableToolReturnInput {
            request: &other_request,
            output: &ToolServerOutput::Value(serde_json::json!({"done": true})),
            reported_cost: None,
            context: &context,
            elapsed: Duration::ZERO,
            trusted_now_unix_ms: current_unix_timestamp_ms(),
        },
    );
    assert!(result
        .as_ref()
        .is_err_and(|error| error.to_string().contains("another operation")));
    assert!(other_store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome
        .is_none());
    assert_eq!(
        other_store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    Ok(())
}
