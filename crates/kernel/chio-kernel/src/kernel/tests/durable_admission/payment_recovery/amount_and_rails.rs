use super::*;

fn quoted_payment(
    name: &str,
    units: u64,
    currency: &str,
) -> (
    ChioKernel,
    ToolCallRequest,
    Arc<TestAdmissionOperationStore>,
    Arc<AtomicU64>,
    Arc<RailCalls>,
) {
    let (kernel, mut request, store, invocations, calls) = payment_fixture(name, true);
    request.governed_intent = Some(make_mustprepay_intent(
        name,
        "durable-server",
        "mutate",
        units,
        currency,
    ));
    (kernel, request, store, invocations, calls)
}

#[test]
fn review_payment_amount_refund_uses_quote_five_and_preserves_exposure_ten() -> TestResult {
    let (kernel, request, store, invocations, calls) =
        quoted_payment("review-payment-quote-five", 5, "USD");
    authorize_without_dispatch(&kernel, &request)?;
    let operation = store.operation();
    let journal = store.payment_journal().ok_or("original journal")?;
    assert_eq!(journal.amount_units, 10);
    let hold = store
        .budget_store()
        .get_budget_hold(
            operation
                .budget_hold_id()
                .ok_or("original hold ID")?
                .as_str(),
        )?
        .ok_or("original hold")?;
    assert_eq!(hold.authorized_exposure_units, 10);
    kernel.compensate_durable_admission_before_dispatch(
        &operation,
        serde_json::json!({"authority": "actual-debit-regression"}),
        current_unix_timestamp_ms(),
        None,
    )?;
    let refunds = calls.refunds.lock().map_err(|_| "refund lock")?;
    assert_eq!(refunds.len(), 1);
    assert_eq!(
        refunds[0].1, 5,
        "refund the actual quote, not the exposure ceiling"
    );
    assert_eq!(refunds[0].2, "USD");
    assert_eq!(refunds[0].3, operation.binding().operation_id().as_str());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn assert_quote_refused_before_any_hold(units: u64, currency: &str) -> TestResult {
    let (kernel, request, store, invocations, calls) =
        quoted_payment("review-payment-unsupported-quote", units, currency);
    assert!(authorize_without_dispatch(&kernel, &request).is_err());
    assert!(store.payment_journal().is_none());
    assert!(store.operation().budget_hold_id().is_none());
    assert!(calls
        .authorizations
        .lock()
        .map_err(|_| "authorization lock")?
        .is_empty());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn review_payment_amount_over_exposure_refuses_before_effect() -> TestResult {
    assert_quote_refused_before_any_hold(100, "USD")
}

#[test]
fn review_payment_amount_currency_mismatch_refuses_before_effect() -> TestResult {
    assert_quote_refused_before_any_hold(5, "EUR")
}

#[test]
fn review_payment_x402_refund_requires_actual_remote_evidence() -> TestResult {
    let adapter = crate::payment::X402PaymentAdapter::new("http://127.0.0.1:1");
    assert!(adapter
        .refund("original-prepayment", 5, "USD", "original-operation")
        .is_err());
    Ok(())
}

#[test]
fn review_payment_x402_release_cannot_undo_final_prepayment() -> TestResult {
    let adapter = crate::payment::X402PaymentAdapter::new("http://127.0.0.1:1");
    assert!(adapter
        .release("original-prepayment", "original-operation")
        .is_err());
    Ok(())
}
