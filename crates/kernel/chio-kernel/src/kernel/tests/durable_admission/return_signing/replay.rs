use super::*;
use crate::admission_operation::AdmissionRecoveryError;

fn compensated_replay_retains_signer(cancelled: bool) -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("compensated-signing-authority");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, 0)
        .map_err(|failure| *failure.error)?
        .ok_or("durable admission")?;
    let mut refusal = compensation_response();
    refusal.cancelled = cancelled;
    let response = kernel.compensate_durable_admission_before_dispatch(
        admission.operation(),
        serde_json::json!({"authority": "receipt-owner"}),
        0,
        None,
        refusal,
    )?;
    drop(admission);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert!(matches!(
        (response.receipt.decision.as_ref(), cancelled),
        (Some(Decision::Deny { .. }), false) | (Some(Decision::Cancelled { .. }), true)
    ));
    let original = store.operation();
    assert_eq!(
        original.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let receipts_before = kernel.receipt_log().len();
    replace_receipt_authority(&mut kernel);
    assert_ne!(
        kernel.receipt_signing_public_key().unwrap(),
        response.receipt.kernel_key
    );
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_same_receipt(&replay.receipt, &response.receipt);
    assert_eq!(replay.verdict, response.verdict);
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.reason, response.reason);
    assert_eq!(replay.terminal_state, response.terminal_state);
    assert_eq!(store.operation(), original);
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn compensated_denial_replay_uses_original_signer_without_reinvocation() -> TestResult {
    compensated_replay_retains_signer(false)
}

#[test]
fn compensated_cancellation_replay_uses_original_signer_without_reinvocation() -> TestResult {
    compensated_replay_retains_signer(true)
}

#[test]
fn completed_replay_rejects_changed_arguments_after_signer_rotation() -> TestResult {
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("rotated-signer-changed-request");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let original = store.operation();
    let receipts_before = kernel.receipt_log().len();
    replace_receipt_authority(&mut kernel);
    request.arguments["value"] = serde_json::json!("changed");
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("changed arguments must refuse replay")?;
    assert!(
        matches!(
            &error,
            KernelError::OperationConflict { operation_id }
                if operation_id == original.binding().operation_id().as_str()
        ),
        "{error:?}"
    );
    assert_eq!(store.operation(), original);
    assert_same_receipt(
        store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .receipt
            .as_ref()
            .ok_or("retained receipt")?,
        &response.receipt,
    );
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn completed_replay_requires_retained_request_after_signer_rotation() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("rotated-signer-missing-request");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let original = store.operation();
    let receipts_before = kernel.receipt_log().len();
    replace_receipt_authority(&mut kernel);
    store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .retained_request = None;
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("missing retained request must refuse replay")?;
    assert!(
        matches!(
            &error,
            KernelError::DurableAdmission(reason)
                if reason == "terminal refusal original request is absent"
        ),
        "{error:?}"
    );
    assert_eq!(store.operation(), original);
    assert_same_receipt(
        store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .receipt
            .as_ref()
            .ok_or("retained receipt")?,
        &response.receipt,
    );
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn completed_replay_rejects_stale_fence_after_signer_rotation() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("rotated-signer-stale-fence");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let original = store.operation();
    let receipts_before = kernel.receipt_log().len();
    replace_receipt_authority(&mut kernel);
    let fence = store.fence.lock().map_err(|_| "fence lock")?.clone();
    store.rotate_fence(StoreMutationFence {
        owner_epoch: fence.owner_epoch + 1,
        ..fence
    });
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("stale fence must refuse replay")?;
    assert!(
        matches!(
            &error,
            KernelError::AdmissionRecovery(failure)
                if matches!(
                    failure.as_ref(),
                    AdmissionRecoveryError::Store(AdmissionOperationStoreError::Fenced)
                )
        ),
        "{error:?}"
    );
    assert_eq!(store.operation(), original);
    assert_same_receipt(
        store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .receipt
            .as_ref()
            .ok_or("retained receipt")?,
        &response.receipt,
    );
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn completed_replay_rejects_failed_lookup_after_signer_rotation() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("rotated-signer-failed-lookup");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let original = store.operation();
    let receipts_before = kernel.receipt_log().len();
    replace_receipt_authority(&mut kernel);
    store.fail_next_replay_read.store(true, Ordering::SeqCst);
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("failed lookup must refuse replay")?;
    assert!(
        matches!(
            &error,
            KernelError::AdmissionRecovery(failure)
                if matches!(
                    failure.as_ref(),
                    AdmissionRecoveryError::Store(AdmissionOperationStoreError::Unavailable(reason))
                        if reason == "injected replay lookup failure"
                )
        ),
        "{error:?}"
    );
    assert_eq!(store.operation(), original);
    assert_same_receipt(
        store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .receipt
            .as_ref()
            .ok_or("retained receipt")?,
        &response.receipt,
    );
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn completed_replay_rejects_another_operation_from_lookup() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("rotated-signer-selector");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let original = store.operation();
    let receipts_before = kernel.receipt_log().len();
    let (other_kernel, other_request, other_store, other_invocations) =
        durable_admission_fixture("rotated-signer-other-selector");
    let other_response = other_kernel.evaluate_tool_call_blocking(&other_request)?;
    assert_eq!(other_response.verdict, Verdict::Allow);
    let other_operation = other_store.operation();
    let other_receipts_before = other_kernel.receipt_log().len();
    assert_ne!(original.replay_key(), other_operation.replay_key());
    replace_receipt_authority(&mut kernel);
    *store
        .replay_lookup_override
        .lock()
        .map_err(|_| "replay lookup override lock")? = Some(other_operation.clone());
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("another operation must refuse replay")?;
    assert!(
        matches!(
            &error,
            KernelError::DurableAdmission(reason)
                if reason == "retained operation does not match its replay selector"
        ),
        "{error:?}"
    );
    assert!(store
        .replay_lookup_override
        .lock()
        .map_err(|_| "replay lookup override lock")?
        .is_none());
    for (actual_store, expected_operation, expected_receipt) in [
        (&store, &original, &response.receipt),
        (&other_store, &other_operation, &other_response.receipt),
    ] {
        assert_eq!(&actual_store.operation(), expected_operation);
        assert_same_receipt(
            actual_store
                .state
                .lock()
                .map_err(|_| "state lock")?
                .receipt
                .as_ref()
                .ok_or("retained receipt")?,
            expected_receipt,
        );
    }
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    assert_eq!(other_kernel.receipt_log().len(), other_receipts_before);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(other_invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
