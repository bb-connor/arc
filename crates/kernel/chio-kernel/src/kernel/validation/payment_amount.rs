//! Durable rails retain the exact debit independently of budget exposure.
use super::*;

impl ChioKernel {
    pub(super) fn durable_payment_authorized_amount(
        request: &ToolCallRequest,
        exposure_units: u64,
        exposure_currency: &str,
    ) -> Result<u64, KernelError> {
        let (amount, currency) = Self::mustprepay_quoted_amount(request)
            .unwrap_or_else(|| (exposure_units, exposure_currency.into()));
        if amount == 0 || amount > exposure_units || currency != exposure_currency {
            return Err(KernelError::AdmissionRecovery(Box::new(
                crate::admission_operation::AdmissionRecoveryError::Item {
                    kind:
                        crate::admission_operation::AdmissionRecoveryFailureKind::UnsupportedState,
                    detail:
                        "durable rail debit must be positive, within exposure, and in its currency"
                            .into(),
                },
            )));
        }
        Ok(amount)
    }

    pub(super) fn validate_durable_payment_authorization_intent(
        adapter: &dyn PaymentAdapter,
        journal: &crate::payment::PaymentJournalRecord,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), PaymentError> {
        let rail_mode = adapter.rail_mode().ok_or_else(|| {
            PaymentError::RailError("durable payment adapter omitted its rail mode".to_owned())
        })?;
        if adapter.rail_id() != journal.rail || rail_mode != journal.rail_mode {
            return Err(PaymentError::RailError(
                "durable payment adapter does not match the persisted rail profile".to_owned(),
            ));
        }
        if journal.currency != currency
            || journal
                .authorized_amount_units
                .is_some_and(|amount| amount != amount_units)
        {
            return Err(PaymentError::RailError(
                "authorization changed the original debit intent".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn begin_durable_payment_authorization_attempt(
        &self,
        admission: &DurableToolAdmission,
        journal: &crate::payment::PaymentJournalRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::payment::PaymentJournalRecord, PaymentError> {
        if journal.authorization_attempt
            != Some(crate::payment::PaymentAuthorizationAttempt::NotStarted)
        {
            return Err(PaymentError::Unavailable("original authorization attempt is unknown; retained recovery must query its reference".into()));
        }
        self.advance_durable_payment_journal(
            admission,
            journal,
            &crate::payment::PaymentJournalTransition::BeginAuthorizationAttempt,
            trusted_now_unix_ms,
        )
        .map_err(|error| PaymentError::RailError(error.to_string()))
    }
}
