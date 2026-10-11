//! Closed journal shapes retain original authorization and settlement facts.
use super::*;

impl PaymentJournalRecord {
    pub(super) fn validate_state_shape(&self) -> Result<(), PaymentJournalError> {
        match self.state {
            PaymentJournalState::HoldPlaced => {
                let expected_version =
                    if self.authorization_attempt == Some(PaymentAuthorizationAttempt::Started) {
                        2
                    } else {
                        1
                    };
                if self.journal_version != expected_version {
                    return Err(PaymentJournalError(
                        "hold_placed version must match its authorization attempt custody"
                            .to_owned(),
                    ));
                }
                self.validate_empty_settlement("hold_placed")?;
            }
            PaymentJournalState::Authorized => {
                if self.rail_mode != PaymentRailMode::ReversibleHold {
                    return Err(PaymentJournalError(
                        "only a reversible rail can retain an authorized hold".to_owned(),
                    ));
                }
                self.require_authorization_id("authorized")?;
                if self.transaction_id.is_some()
                    || self.settle_action.is_some()
                    || self.settle_amount_units.is_some()
                    || self.release_authority.is_some()
                {
                    return Err(PaymentJournalError(
                        "authorized state cannot contain a terminal settle result".to_owned(),
                    ));
                }
            }
            PaymentJournalState::Settling => {
                self.require_authorization_id("settling")?;
                if self.transaction_id.is_some() {
                    return Err(PaymentJournalError(
                        "settling cannot contain a terminal transaction_id".to_owned(),
                    ));
                }
                if self.rail_mode == PaymentRailMode::PrepaidFinal {
                    self.validate_prepaid_refund()?;
                } else {
                    self.validate_settle_intent()?;
                }
            }
            PaymentJournalState::Closed if self.authorization_id.is_none() => {
                let expected_version =
                    if self.authorization_attempt == Some(PaymentAuthorizationAttempt::Started) {
                        3
                    } else {
                        2
                    };
                if self.journal_version != expected_version {
                    return Err(PaymentJournalError(
                        "pre-authorization cancellation version conflicts with attempt custody"
                            .to_owned(),
                    ));
                }
                self.validate_empty_settlement("pre-authorization cancellation")?;
            }
            PaymentJournalState::Settled | PaymentJournalState::Closed => {
                self.require_authorization_id("terminal")?;
                match self.rail_mode {
                    PaymentRailMode::PrepaidFinal => {
                        if self.state == PaymentJournalState::Closed
                            && self.release_authority.is_some()
                        {
                            self.validate_prepaid_refund()?;
                            if self.transaction_id.is_none() {
                                return Err(PaymentJournalError(
                                    "refunded prepayment requires its rail transaction".into(),
                                ));
                            }
                        } else if self.transaction_id.is_some()
                            || self.settle_action.is_some()
                            || self.settle_amount_units.is_some()
                            || self.release_authority.is_some()
                        {
                            return Err(PaymentJournalError(
                                "final prepayment cannot contain synthetic settlement fields"
                                    .to_owned(),
                            ));
                        }
                    }
                    PaymentRailMode::ReversibleHold => {
                        if self.transaction_id.is_none() {
                            return Err(PaymentJournalError(
                                "a terminal reversible hold requires transaction_id".to_owned(),
                            ));
                        }
                        self.validate_settle_intent()?;
                    }
                }
            }
            PaymentJournalState::ReconcileFailed => self.validate_reconcile_shape()?,
        }
        Ok(())
    }
}
