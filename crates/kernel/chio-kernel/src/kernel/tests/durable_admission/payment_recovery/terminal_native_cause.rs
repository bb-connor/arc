//! Real paid calls retain their terminal store error after a known rail outcome.
use super::*;
use std::error::Error;

#[test]
fn review_terminal_native_completed_projection_retains_cause_and_fatal_scope() -> TestResult {
    check_terminal_projection_cause(false)
}

#[test]
fn review_terminal_native_denied_projection_retains_cause_and_fatal_scope() -> TestResult {
    check_terminal_projection_cause(true)
}

fn assert_native_projection_error(error: &KernelError) -> TestResult {
    assert_eq!(error.report().code, "CHIO-KERNEL-RECEIPT-PERSISTENCE");
    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(_))
    ));
    let source = error.source().ok_or("original terminal receipt error")?;
    let original = source
        .downcast_ref::<ReceiptStoreError>()
        .ok_or("original ReceiptStoreError type")?;
    assert!(matches!(original, ReceiptStoreError::Conflict(detail)
        if detail == "injected terminal projection failure"));
    Ok(())
}

fn check_terminal_projection_cause(denied: bool) -> TestResult {
    let original_time = chio_test_support::clock::unix_seconds();
    let _original_clock = chio_test_support::clock::scope_unix_secs(original_time);
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".into(),
    });
    if denied {
        grant
            .constraints
            .push(crate::Constraint::OutputDigestSha256("a".repeat(64)));
    }
    let name = if denied {
        "review-native-denied-projection"
    } else {
        "review-native-completed-projection"
    };
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture_with_grants(name, vec![grant]);
    let calls = Arc::new(RailCalls::default());
    kernel.set_payment_adapter(Box::new(RecoveryRail {
        prepaid: false,
        calls: calls.clone(),
    }));
    store.fail_next_terminal_projection();
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("original projection failure")?;
    assert!(
        !store.fail_next_terminal_projection.load(Ordering::SeqCst),
        "the original real call must reach the terminal store boundary"
    );
    let original = store.operation();
    assert_eq!(original.state(), AdmissionOperationState::Finalizing);
    let journal = store
        .payment_journal()
        .ok_or("actual settled original journal")?;
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(
        journal.settle_action,
        Some(if denied {
            PaymentSettleAction::Release
        } else {
            PaymentSettleAction::Capture
        })
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization trace")?
            .as_slice(),
        [original.binding().operation_id().as_str()]
    );
    assert_eq!(
        calls.captures.lock().map_err(|_| "capture trace")?.len(),
        usize::from(!denied)
    );
    assert_eq!(
        calls.releases.lock().map_err(|_| "release trace")?.len(),
        usize::from(denied)
    );
    assert_native_projection_error(&error)?;

    // Expire only the original coordinator claim, keeping its budget authority.
    let _due_clock = chio_test_support::clock::scope_unix_secs(
        original_time.checked_add(120).ok_or("claim expiry")?,
    );
    store.fail_next_terminal_projection();
    let recovery_error = kernel
        .reconcile_recoverable_admissions()
        .err()
        .ok_or("the original store error must remain globally fatal")?;
    assert_native_projection_error(&recovery_error)?;
    assert_eq!(store.operation(), original);
    assert_eq!(store.payment_journal(), Some(journal.clone()));
    assert!(
        store
            .state
            .lock()
            .map_err(|_| "recovery state")?
            .recovery_status
            .is_none(),
        "global native failure must not become item quarantine"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls.captures.lock().map_err(|_| "capture trace")?.len(),
        usize::from(!denied)
    );
    assert_eq!(
        calls.releases.lock().map_err(|_| "release trace")?.len(),
        usize::from(denied)
    );
    assert!(calls.refunds.lock().map_err(|_| "refund trace")?.is_empty());

    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(
        replay.verdict,
        if denied {
            Verdict::Deny
        } else {
            Verdict::Allow
        }
    );
    assert!(replay.receipt.verify_signature()?);
    assert_eq!(
        store.operation().state(),
        if denied {
            AdmissionOperationState::DeniedAfterDelivery
        } else {
            AdmissionOperationState::Completed
        }
    );
    assert_eq!(store.payment_journal(), Some(journal));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization trace")?
            .len(),
        1
    );
    assert_eq!(
        calls.captures.lock().map_err(|_| "capture trace")?.len(),
        usize::from(!denied)
    );
    assert_eq!(
        calls.releases.lock().map_err(|_| "release trace")?.len(),
        usize::from(denied)
    );
    assert!(calls.refunds.lock().map_err(|_| "refund trace")?.is_empty());
    Ok(())
}
