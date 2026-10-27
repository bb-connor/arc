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
        compensation_response(),
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
    let error = authorize_without_dispatch(&kernel, &request)
        .err()
        .ok_or("lost authorization acknowledgement was accepted")?;
    assert!(
        matches!(error.downcast_ref::<PaymentError>(), Some(PaymentError::Unavailable(detail))
        if detail == "authorization acknowledgement lost")
    );
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
        compensation_response(),
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

/// Runs the sim rail and then stops before its authorization id reaches the
/// payment journal, as a process crash between the two would.
struct SimRailStoppedBeforeJournal {
    inner: crate::payment::SimPaymentAdapter,
    authorized: Arc<Mutex<Vec<String>>>,
}

impl PaymentAdapter for SimRailStoppedBeforeJournal {
    fn rail_id(&self) -> &'static str {
        self.inner.rail_id()
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.inner.rail_mode()
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let authorization = self.inner.authorize(request)?;
        self.authorized
            .lock()
            .map_err(|_| PaymentError::RailError("authorization lock".into()))?
            .push(authorization.authorization_id);
        Err(PaymentError::Unavailable(
            "process stopped before the sim authorization reached the journal".into(),
        ))
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .capture(authorization_id, amount_units, currency, reference)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.release(authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.inner.settlement_state(reference, authorization_id)
    }
}

#[test]
fn review_payment_authorization_window_sim_crash_before_journal_refunds_the_recorded_prepayment(
) -> TestResult {
    let authorized = Arc::new(Mutex::new(Vec::new()));
    let sim = crate::payment::SimPaymentAdapter::new();
    let (kernel, request, store, invocations) = payment_fixture_with_adapter(
        "review-payment-sim-crash-before-journal",
        Box::new(SimRailStoppedBeforeJournal {
            inner: sim.clone(),
            authorized: authorized.clone(),
        }),
    );
    let error = authorize_without_dispatch(&kernel, &request)
        .err()
        .ok_or("sim authorization that never reached the journal was accepted")?;
    assert!(
        matches!(error.downcast_ref::<PaymentError>(), Some(PaymentError::Unavailable(detail))
        if detail == "process stopped before the sim authorization reached the journal")
    );
    let authorization_id = authorized
        .lock()
        .map_err(|_| "authorization lock")?
        .first()
        .cloned()
        .ok_or("sim authorization")?;
    let journal = store.payment_journal().ok_or("ambiguous journal")?;
    assert_eq!(journal.state, PaymentJournalState::HoldPlaced);
    assert_eq!(journal.rail_mode, PaymentRailMode::PrepaidFinal);
    assert_eq!(journal.authorization_id, None);

    let operation = store.operation();
    kernel.compensate_durable_admission_before_dispatch(
        &operation,
        serde_json::json!({"authority": "sim-crash-before-journal"}),
        current_unix_timestamp_ms(),
        None,
        compensation_response(),
    )?;
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let journal = store.payment_journal().ok_or("closed journal")?;
    assert_eq!(journal.state, PaymentJournalState::Closed);
    assert_eq!(
        journal.authorization_id.as_deref(),
        Some(authorization_id.as_str())
    );
    let crate::payment::RailSettlementState::Settled { result, .. } =
        sim.settlement_state(&journal.operation_id, Some(&authorization_id))?
    else {
        return Err("recovered sim authorization has no settled state".into());
    };
    assert_eq!(
        result.settlement_status,
        crate::payment::RailSettlementStatus::Refunded
    );
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
