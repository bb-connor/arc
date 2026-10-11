//! A settled prepayment without its exact debit stays quarantined with its liability.
//! The unit store models the journal shape the schema-12 store migration leaves
//! for a legacy row; it does not run that SQLite migration.
use super::*;
use crate::admission_operation::{AdmissionRecoveryFailureKind, AdmissionRecoveryStatusV1};
use crate::budget_store::BudgetHoldDispositionView;

#[test]
fn review_legacy_settled_prepaid_quarantines_with_exact_legacy_amount_absent() -> TestResult {
    let (kernel, request, store, invocations, calls) =
        payment_fixture("review-legacy-settled-prepaid", true);
    store.fail_next_payment_settlement_intent();
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("injected settlement intent failure was accepted")?;
    assert!(matches!(error, KernelError::AdmissionRecovery(failure)
        if matches!(failure.as_ref(), crate::admission_operation::AdmissionRecoveryError::PaymentJournal(
            crate::receipt_store::AdmissionPaymentJournalError::OutcomeUnknown(reason)
        ) if reason == "injected payment settlement intent failure")));
    let operation = store.operation();
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    {
        let mut state = store.state.lock().map_err(|_| "fixture state lock")?;
        let journal = state
            .payment_journal
            .as_mut()
            .ok_or("settled prepaid journal")?;
        assert_eq!(
            (
                journal.rail_mode,
                journal.state,
                journal.authorized_amount_units
            ),
            (
                PaymentRailMode::PrepaidFinal,
                PaymentJournalState::Settled,
                Some(10)
            )
        );
        journal.journal_version = 1;
        journal.authorization_attempt = None;
        journal.authorized_amount_units = None;
        journal.validate()?;
    }
    let claim_expired_at = chio_test_support::clock::unix_seconds()
        .checked_add(120)
        .ok_or("claim expiry time")?;
    let _claim_expired = chio_test_support::clock::scope_unix_secs(claim_expired_at);

    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);

    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    let journal = store.payment_journal().ok_or("retained legacy journal")?;
    assert_eq!(
        (
            journal.state,
            journal.authorized_amount_units,
            journal.authorization_id.as_deref()
        ),
        (
            PaymentJournalState::Settled,
            None,
            Some("original-payment-authorization")
        )
    );
    let hold = store
        .budget_store()
        .get_budget_hold(operation.budget_hold_id().ok_or("hold ID")?.as_str())?
        .ok_or("original budget hold")?;
    assert_eq!(
        (hold.disposition, hold.remaining_exposure_units),
        (BudgetHoldDispositionView::Open, 10)
    );
    let fence = store
        .fence
        .lock()
        .map_err(|_| "fixture fence lock")?
        .clone();
    let AdmissionRecoveryStatusV1 {
        quarantined,
        deferral,
    } = store
        .load_recovery_status(
            operation.binding().operation_id(),
            &fence,
            current_unix_timestamp_ms(),
        )?
        .ok_or("typed legacy deferral")?;
    assert!(quarantined);
    assert_eq!(
        deferral.failure_kind,
        AdmissionRecoveryFailureKind::LegacyPaymentAmountAbsent
    );
    assert!(calls.refunds.lock().map_err(|_| "test lock")?.is_empty());
    assert!(calls.captures.lock().map_err(|_| "test lock")?.is_empty());
    assert!(calls.releases.lock().map_err(|_| "test lock")?.is_empty());
    assert_eq!(
        calls.authorizations.lock().map_err(|_| "test lock")?.len(),
        1
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
