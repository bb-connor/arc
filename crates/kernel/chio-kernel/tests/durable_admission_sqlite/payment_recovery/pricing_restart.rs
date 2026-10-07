//! A Resolved financial plan survives a new owner and changed FX availability.
use super::*;
#[path = "pricing_restart/fixture.rs"]
mod fixture;
use fixture::*;

#[test]
fn sqlite_review_frozen_pricing_restart_uses_original_fx_before_pending_capture(
) -> Result<(), Box<dyn Error>> {
    restart_pricing(
        "sqlite-frozen-fx-restart",
        1_000_000_000_000_000,
        "ETH",
        true,
        1,
        None,
    )
}
#[test]
fn sqlite_review_frozen_pricing_restart_caps_overreported_cost_and_preserves_failed_pricing(
) -> Result<(), Box<dyn Error>> {
    restart_pricing(
        "sqlite-overreported-restart",
        100,
        "USD",
        false,
        10,
        Some("authorization_exceeded"),
    )
}
#[test]
fn sqlite_review_frozen_pricing_restart_caps_unconvertible_cost_without_fresh_oracle(
) -> Result<(), Box<dyn Error>> {
    restart_pricing(
        "sqlite-unconvertible-restart",
        1_000_000_000_000_000,
        "ETH",
        false,
        10,
        Some("conversion_unavailable"),
    )
}

fn restart_pricing(
    request_id: &str,
    units: u64,
    currency: &'static str,
    original_oracle: bool,
    charged: u64,
    failure: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let at = 1_800_000_400_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let (_temp, database, locks) = provision()?;
    let keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let facts = Arc::new(PricingFacts::default());
    facts.calls.fail_next_capture.store(true, Ordering::SeqCst);
    facts.rate.store(10, Ordering::SeqCst);
    let (request, operation_id) = {
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            chio_test_support::clock::clock(),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel = ChioKernel::new_with_clock(
            kernel_config(keypair.clone()),
            chio_test_support::clock::clock(),
        );
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(TracedCapture(facts.clone())));
        if original_oracle {
            kernel.set_price_oracle(Box::new(MovingRate(facts.clone())));
        }
        kernel.register_tool_server(Box::new(CostServer {
            invocations: invocations.clone(),
            units,
            currency,
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let mut request = paid_request(&capability);
        request.request_id = request_id.into();
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .err()
            .ok_or("original capture must be interrupted")?;
        ordinary_operation::assert_interrupted_payment(&error, "injected capture interruption")?;
        let traces = facts.captures.lock().map_err(|_| "capture trace lock")?;
        let [(reference, amount, currency)] = traces.as_slice() else {
            return Err("expected one original capture reference".into());
        };
        assert_eq!(*amount, charged);
        assert_eq!(currency, "USD");
        let original = ordinary_operation::from_rail_reference(
            operations.as_ref(),
            &fence,
            &request,
            reference,
        )?;
        assert_eq!(original.state(), AdmissionOperationState::Finalizing);
        let id = original.binding().operation_id().clone();
        let journal = operations
            .load_payment_journal(id.as_str(), &fence)?
            .ok_or("original capture journal")?;
        assert_eq!(journal.state, PaymentJournalState::Settling);
        assert_eq!(journal.settle_amount_units, Some(charged));
        (request, id)
    };
    assert_eq!(
        facts.oracle_calls.load(Ordering::SeqCst),
        u64::from(original_oracle)
    );
    facts.rate.store(20, Ordering::SeqCst);
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        chio_test_support::clock::clock(),
    )?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let mut kernel =
        ChioKernel::new_with_clock(kernel_config(keypair), chio_test_support::clock::clock());
    kernel.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        fence.clone(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(TracedCapture(facts.clone())));
    // A converter now exists even for the original unavailable-conversion plan.
    kernel.set_price_oracle(Box::new(MovingRate(facts.clone())));
    kernel.register_tool_server(Box::new(CostServer {
        invocations: invocations.clone(),
        units,
        currency,
    }));
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
    let completed = operations
        .load_by_operation_id(&operation_id)?
        .ok_or("completed original operation")?;
    assert_eq!(completed.state(), AdmissionOperationState::Completed);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or("settled original capture")?;
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_amount_units, Some(charged));
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(
        response.output,
        Some(chio_kernel::ToolCallOutput::Value(
            serde_json::json!({"original_paid_output": true}),
        ))
    );
    assert!(response.receipt.verify_signature()?);
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .ok_or("financial metadata")?;
    assert_eq!(
        financial
            .get("cost_charged")
            .and_then(serde_json::Value::as_u64),
        Some(charged)
    );
    if original_oracle {
        assert_eq!(
            financial
                .get("oracle_evidence")
                .and_then(|evidence| evidence.get("converted_cost_units"))
                .and_then(serde_json::Value::as_u64),
            Some(charged)
        );
    }
    if let Some(failure) = failure {
        assert_eq!(
            financial
                .get("settlement_status")
                .and_then(serde_json::Value::as_str),
            Some("failed")
        );
        let payment = financial
            .get("cost_breakdown")
            .and_then(|breakdown| breakdown.get("payment"))
            .ok_or("payment cost facts")?;
        assert_eq!(
            payment
                .get("pricing_failure")
                .and_then(serde_json::Value::as_str),
            Some(failure)
        );
        let reported = payment.get("reported_cost").ok_or("reported cost facts")?;
        assert_eq!(
            reported.get("units").and_then(serde_json::Value::as_u64),
            Some(units)
        );
        assert_eq!(
            reported.get("currency").and_then(serde_json::Value::as_str),
            Some(currency)
        );
    }
    assert_eq!(
        facts
            .captures
            .lock()
            .map_err(|_| "capture trace lock")?
            .as_slice(),
        &[
            (operation_id.as_str().to_owned(), charged, "USD".into()),
            (operation_id.as_str().to_owned(), charged, "USD".into()),
        ]
    );
    assert_eq!(
        facts.oracle_calls.load(Ordering::SeqCst),
        u64::from(original_oracle)
    );
    assert_eq!(facts.calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(facts.calls.captures.load(Ordering::SeqCst), 2);
    assert_eq!(facts.calls.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(facts.calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let bytes = canonical_json_bytes(&response.receipt)?;
    assert_eq!(
        canonical_json_bytes(&kernel.evaluate_tool_call_blocking(&request)?.receipt)?,
        bytes
    );
    assert_eq!(facts.calls.captures.load(Ordering::SeqCst), 2);
    Ok(())
}
