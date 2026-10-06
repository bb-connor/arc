use super::*;
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "payment_recovery/fixture.rs"]
mod fixture;
use fixture::*;
#[path = "payment_recovery/cost_support.rs"]
mod cost_support;
use cost_support::*;
#[path = "payment_recovery/amount_and_rails.rs"]
mod amount_and_rails;
#[path = "payment_recovery/authorization_window.rs"]
mod authorization_window;
#[path = "payment_recovery/continuation_controls.rs"]
mod continuation_controls;
#[cfg(feature = "finding-market")]
#[path = "payment_recovery/publication.rs"]
mod publication;
#[path = "payment_recovery/status_only_refund.rs"]
mod status_only_refund;
#[path = "payment_recovery/terminal_native_cause.rs"]
mod terminal_native_cause;

#[test]
fn review_payment_prepaid_compensation_refunds_original_payment() -> TestResult {
    let (kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-prepaid", true);
    authorize_without_dispatch(&kernel, &request)?;
    let operation = store.operation();
    kernel.compensate_durable_admission_before_dispatch(
        &operation,
        serde_json::json!({"authority": "review-regression"}),
        current_unix_timestamp_ms(),
        None,
    )?;
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        store.payment_journal().ok_or("refunded journal")?.state,
        PaymentJournalState::Closed
    );
    assert_eq!(
        calls.refunds.lock().map_err(|_| "test lock")?.as_slice(),
        [(
            "original-payment-authorization".into(),
            10,
            "USD".into(),
            operation.binding().operation_id().as_str().into()
        )]
    );
    assert!(calls.releases.lock().map_err(|_| "test lock")?.is_empty());
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn review_payment_compensation_retries_original_release_intent() -> TestResult {
    let (kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-release-retry", false);
    authorize_without_dispatch(&kernel, &request)?;
    calls.release_failed.store(true, Ordering::SeqCst);
    let operation = store.operation();
    let policy = serde_json::json!({"authority": "review-regression"});
    assert!(kernel
        .compensate_durable_admission_before_dispatch(
            &operation,
            policy.clone(),
            current_unix_timestamp_ms(),
            None
        )
        .is_err());
    assert_eq!(
        store.payment_journal().ok_or("pending journal")?.state,
        PaymentJournalState::Settling
    );
    kernel.compensate_durable_admission_before_dispatch(
        &operation,
        policy,
        current_unix_timestamp_ms(),
        None,
    )?;
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        calls.releases.lock().map_err(|_| "test lock")?.as_slice(),
        [
            operation.binding().operation_id().as_str(),
            operation.binding().operation_id().as_str()
        ]
    );
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn assert_cost_terminal(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    store: &TestAdmissionOperationStore,
    calls: &RailCalls,
    invocations: &AtomicU64,
    failure: &str,
) -> TestResult {
    let response = kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"paid_output": true})
        ))
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let journal = store.payment_journal().ok_or("settled journal")?;
    assert_eq!(
        (journal.state, journal.settle_amount_units),
        (PaymentJournalState::Settled, Some(10))
    );
    let financial = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or("financial metadata")?["financial"];
    assert_eq!(financial["cost_charged"], 10);
    assert_eq!(financial["settlement_status"], "failed");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["pricing_failure"],
        failure
    );
    let replay = kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(calls.captures.lock().map_err(|_| "test lock")?.len(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn review_payment_overreported_cost_caps_capture_and_terminates() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-overreported", false);
    kernel.register_tool_server(Box::new(ReportedCostServer {
        units: 25,
        currency: "USD",
        invocations: invocations.clone(),
    }));
    assert_cost_terminal(
        &kernel,
        &request,
        &store,
        &calls,
        &invocations,
        "authorization_exceeded",
    )
}

#[test]
fn review_payment_unconvertible_cost_caps_capture_and_terminates() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-no-oracle", false);
    kernel.register_tool_server(Box::new(ReportedCostServer {
        units: 1_000_000_000_000_000,
        currency: "ETH",
        invocations: invocations.clone(),
    }));
    assert_cost_terminal(
        &kernel,
        &request,
        &store,
        &calls,
        &invocations,
        "conversion_unavailable",
    )
}

#[test]
fn review_payment_resolved_replay_preserves_original_fx_disposition() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-moving-fx", false);
    let rate = Arc::new(AtomicU64::new(10));
    let oracle_calls = Arc::new(AtomicU64::new(0));
    kernel.set_price_oracle(Box::new(MovingOracle {
        rate: rate.clone(),
        calls: oracle_calls.clone(),
    }));
    kernel.register_tool_server(Box::new(ReportedCostServer {
        units: 1_000_000_000_000_000,
        currency: "ETH",
        invocations: invocations.clone(),
    }));
    calls.capture_pending.store(true, Ordering::SeqCst);
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(
        store
            .payment_journal()
            .ok_or("pending journal")?
            .settle_amount_units,
        Some(1)
    );
    rate.store(20, Ordering::SeqCst);
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(
        calls.captures.lock().map_err(|_| "test lock")?.as_slice(),
        [
            (
                store.operation().binding().operation_id().as_str().into(),
                1
            ),
            (
                store.operation().binding().operation_id().as_str().into(),
                1
            )
        ]
    );
    assert_eq!(oracle_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let financial = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or("financial metadata")?["financial"];
    assert_eq!(financial["oracle_evidence"]["converted_cost_units"], 1);
    Ok(())
}

#[test]
fn review_payment_startup_isolates_an_unrecoverable_operation() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("review-payment-startup-isolation");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "original",
    }));
    store.fail_next_evaluation_begin();
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    let mut fence = admission_test_fence();
    fence.lease_id = "review-recovery-owner".into();
    fence.owner_epoch = 2;
    store.rotate_fence(fence.clone());
    let mut config = make_config();
    config.keypair = kernel.config.keypair.clone();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered = make_kernel(config);
    recovered.set_durable_admission_store(store.clone(), store.clone(), fence)?;
    recovered.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "changed",
    }));
    assert_eq!(recovered.reconcile_durable_admission_startup()?, 0);
    assert_eq!(recovered.reconcile_durable_admission_startup()?, 0);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn review_payment_live_prepaid_refusal_signs_deny_after_confirmed_refund() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("review-payment-live-prepaid-refusal", true);
    kernel.add_post_invocation_hook(Box::new(PrepaymentRefusalHook(store.clone())));
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(calls.refunds.lock().map_err(|_| "test lock")?.len(), 1);
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
