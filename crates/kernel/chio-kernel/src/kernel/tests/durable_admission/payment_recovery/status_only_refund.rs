//! Status-only query replies do not attest how much of a prepayment was refunded.
//! The unit store seeds a checked acknowledgement-loss snapshot. This is not a
//! qualification of a migrated native store or a live external payment service.
use super::*;
use crate::admission_operation::{AdmissionRecoveryFailureKind, AdmissionRecoveryStatusV1};
use crate::payment::{PaymentAuthorizationAttempt, RailSettlementState};

struct QueryRail {
    inner: RecoveryRail,
    observed: PaymentResult,
}
impl PaymentAdapter for QueryRail {
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
        self.inner.authorize(request)
    }
    fn capture(
        &self,
        id: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.capture(id, amount, currency, reference)
    }
    fn release(&self, id: &str, reference: &str) -> Result<PaymentResult, PaymentError> {
        self.inner.release(id, reference)
    }
    fn refund(
        &self,
        id: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.refund(id, amount, currency, reference)
    }
    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        if authorization_id.is_some()
            || !self
                .inner
                .calls
                .authorizations
                .lock()
                .map_err(|_| PaymentError::Unavailable("original reference lock".into()))?
                .iter()
                .any(|original| original == reference)
        {
            return Err(PaymentError::RailError(
                "query changed original reference".into(),
            ));
        }
        self.inner
            .calls
            .queries
            .lock()
            .map_err(|_| PaymentError::Unavailable("query trace lock".into()))?
            .push(reference.into());
        Ok(RailSettlementState::Settled {
            authorization_id: "original-payment-authorization".into(),
            result: self.observed.clone(),
        })
    }
}

#[test]
fn review_status_only_prepaid_refund_with_known_debit_retains_remaining_liability() -> TestResult {
    check_partial_refund(false)
}
#[test]
fn review_status_only_prepaid_refund_with_legacy_unknown_debit_retains_liability() -> TestResult {
    check_partial_refund(true)
}

fn interrupted_authorization(store: &TestAdmissionOperationStore, legacy: bool) -> TestResult {
    let mut state = store.state.lock().map_err(|_| "fixture state lock")?;
    let journal = state
        .payment_journal
        .as_mut()
        .ok_or("initial paid journal")?;
    assert_eq!(journal.authorized_amount_units, Some(10));
    assert_eq!(
        journal.authorization_id.as_deref(),
        Some("original-payment-authorization")
    );
    // Represent the earlier checkpoint before the acknowledgement reached the
    // local journal. Optional fields are absent only for the legacy format.
    journal.journal_version = if legacy { 1 } else { 2 };
    journal.state = PaymentJournalState::HoldPlaced;
    journal.authorization_id = None;
    journal.authorization_attempt = if legacy {
        None
    } else {
        Some(PaymentAuthorizationAttempt::Started)
    };
    if legacy {
        journal.authorized_amount_units = None;
    }
    journal.validate()?;
    Ok(())
}

fn expire_original_coordinator_claim(
) -> Result<chio_test_support::clock::ClockScope, Box<dyn std::error::Error>> {
    let after = chio_test_support::clock::unix_seconds()
        .checked_add(120)
        .ok_or("claim expiry time")?;
    Ok(chio_test_support::clock::scope_unix_secs(after))
}

fn check_partial_refund(legacy: bool) -> TestResult {
    let name = if legacy {
        "review-status-legacy-partial-refund"
    } else {
        "review-status-known-partial-refund"
    };
    let (mut kernel, request, store, invocations, calls) = payment_fixture(name, true);
    authorize_without_dispatch(&kernel, &request)?;
    let operation = store.operation();
    let rail = RecoveryRail {
        prepaid: true,
        calls: calls.clone(),
    };
    // A valid refund callback attests only the five units that were requested,
    // while the original authorized debit was ten. The state DTO carries no
    // amount or whole-debit attestation for this status-only query response.
    let partial = rail.refund(
        "original-payment-authorization",
        5,
        "USD",
        operation.binding().operation_id().as_str(),
    )?;
    assert_eq!(partial.settlement_status, RailSettlementStatus::Refunded);
    assert_eq!(
        calls
            .refunds
            .lock()
            .map_err(|_| "refund trace lock")?
            .as_slice(),
        &[(
            "original-payment-authorization".into(),
            5,
            "USD".into(),
            operation.binding().operation_id().as_str().to_owned(),
        )]
    );
    interrupted_authorization(&store, legacy)?;
    kernel.set_payment_adapter(Box::new(QueryRail {
        inner: rail,
        observed: partial,
    }));
    // Preserve the original hold's authority/lease. Only its coordinator claim
    // expires; this unit store does not implement native budget lease handoff.
    let _claim_expired = expire_original_coordinator_claim()?;
    assert_eq!(
        kernel.reconcile_durable_admission_startup()?,
        0,
        "a partial refund cannot close the whole original debit"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::BudgetAuthorized
    );
    let journal = store
        .payment_journal()
        .ok_or("remaining liability journal")?;
    assert!(!journal.is_compensated_before_dispatch());
    let hold = store
        .budget_store()
        .get_budget_hold(operation.budget_hold_id().ok_or("hold ID")?.as_str())?
        .ok_or("original budget hold")?;
    assert_eq!(hold.remaining_exposure_units, 10);
    let fence = store
        .fence
        .lock()
        .map_err(|_| "fixture fence lock")?
        .clone();
    let status = store
        .load_recovery_status(
            operation.binding().operation_id(),
            &fence,
            current_unix_timestamp_ms(),
        )?
        .ok_or("typed original deferral")?;
    let AdmissionRecoveryStatusV1 {
        quarantined,
        deferral,
    } = status;
    assert!(quarantined);
    assert!(matches!(
        deferral.failure_kind,
        AdmissionRecoveryFailureKind::ContractChanged
            | AdmissionRecoveryFailureKind::LegacyPaymentAmountAbsent
    ));
    assert_eq!(
        calls
            .queries
            .lock()
            .map_err(|_| "query trace lock")?
            .as_slice(),
        &[operation.binding().operation_id().as_str().to_owned()]
    );
    assert_eq!(
        calls.refunds.lock().map_err(|_| "refund trace lock")?.len(),
        1
    );
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization trace lock")?
            .len(),
        1
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn review_status_only_original_prepaid_settled_query_refunds_exact_known_debit() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("review-status-settled-prepaid", true);
    authorize_without_dispatch(&kernel, &request)?;
    let operation = store.operation();
    interrupted_authorization(&store, false)?;
    let rail = QueryRail {
        inner: RecoveryRail {
            prepaid: true,
            calls: calls.clone(),
        },
        observed: PaymentResult {
            transaction_id: "original-payment-authorization".into(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        },
    };
    kernel.set_payment_adapter(Box::new(rail));
    let _claim_expired = expire_original_coordinator_claim()?;
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_released_budget(&store)?;
    assert_eq!(
        calls
            .refunds
            .lock()
            .map_err(|_| "refund trace lock")?
            .as_slice(),
        &[(
            "original-payment-authorization".into(),
            10,
            "USD".into(),
            operation.binding().operation_id().as_str().to_owned(),
        )]
    );
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization trace lock")?
            .len(),
        1
    );
    assert_eq!(
        calls
            .queries
            .lock()
            .map_err(|_| "query trace lock")?
            .as_slice(),
        &[operation.binding().operation_id().as_str().to_owned()]
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
