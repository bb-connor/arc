//! Original debit and phase evidence are immutable facts, apart from one attempt.
use super::*;

impl PaymentJournalRecord {
    pub(super) fn validate_authorization_custody(&self) -> Result<(), PaymentJournalError> {
        if self
            .authorized_amount_units
            .is_some_and(|amount| amount == 0 || amount > self.amount_units)
        {
            return Err(PaymentJournalError(
                "rail authorized amount must fit original budget exposure".into(),
            ));
        }
        if let Some(attempt) = self.authorization_attempt {
            if self.authorized_amount_units.is_none() {
                return Err(PaymentJournalError(
                    "authorization attempt custody requires the exact debit".into(),
                ));
            }
            match attempt {
                PaymentAuthorizationAttempt::NotStarted
                    if !matches!(
                        self.state,
                        PaymentJournalState::HoldPlaced | PaymentJournalState::Closed
                    ) || self.authorization_id.is_some() =>
                {
                    return Err(PaymentJournalError(
                        "not-started custody cannot retain a rail authorization".into(),
                    ));
                }
                PaymentAuthorizationAttempt::Started if self.journal_version < 2 => {
                    return Err(PaymentJournalError(
                        "started custody requires its durable attempt mutation".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
