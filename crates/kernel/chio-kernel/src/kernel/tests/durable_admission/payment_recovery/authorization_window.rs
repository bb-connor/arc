use super::*;

#[test]
fn review_payment_authorization_window_never_attempted_can_compensate_without_query() -> TestResult
{
    let (kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-never-attempted", true);
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(&request, &matching, now)?
        .ok_or("original admission")?;
    kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    drop(admission);
    let operation = store.operation();
    kernel.compensate_durable_admission_before_dispatch(
        &operation,
        serde_json::json!({"authority": "never-attempted-regression"}),
        now,
        None,
    )?;
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(calls
        .authorizations
        .lock()
        .map_err(|_| "authorization lock")?
        .is_empty());
    assert!(calls.queries.lock().map_err(|_| "query lock")?.is_empty());
    assert!(calls.refunds.lock().map_err(|_| "refund lock")?.is_empty());
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn review_payment_authorization_window_lost_ack_queries_original_reference_before_release(
) -> TestResult {
    let (kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-lost-ack", false);
    calls.authorization_failed.store(true, Ordering::SeqCst);
    calls.query_supported.store(true, Ordering::SeqCst);
    assert!(authorize_without_dispatch(&kernel, &request).is_err());
    let operation = store.operation();
    assert_eq!(
        store.payment_journal().ok_or("ambiguous journal")?.state,
        PaymentJournalState::HoldPlaced
    );
    kernel.compensate_durable_admission_before_dispatch(
        &operation,
        serde_json::json!({"authority": "lost-ack-regression"}),
        current_unix_timestamp_ms(),
        None,
    )?;
    let original_reference = operation.binding().operation_id().as_str();
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization lock")?
            .as_slice(),
        [original_reference]
    );
    assert_eq!(
        calls.queries.lock().map_err(|_| "query lock")?.as_slice(),
        [original_reference]
    );
    assert_eq!(
        calls
            .releases
            .lock()
            .map_err(|_| "release lock")?
            .as_slice(),
        [original_reference]
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
