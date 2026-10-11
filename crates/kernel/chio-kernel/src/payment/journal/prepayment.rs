//! A refunded prepayment retains the original authorization and no-effect proof.

use super::*;

impl PaymentJournalRecord {
    pub(super) fn validate_prepaid_refund(&self) -> Result<(), PaymentJournalError> {
        self.require_authorization_id("prepayment refund")?;
        if self.settle_action.is_some() || self.settle_amount_units.is_some() {
            return Err(PaymentJournalError(
                "prepayment refund cannot contain reversible settlement fields".into(),
            ));
        }
        let authority = self.release_authority.as_ref().ok_or_else(|| {
            PaymentJournalError("prepayment refund requires verified no-effect authority".into())
        })?;
        authority.validate_for(&self.operation_id)?;
        if authority.kind != PaymentReleaseAuthorityKind::PreDispatchNoEffect {
            return Err(PaymentJournalError(
                "prepayment refund requires pre-dispatch no-effect authority".into(),
            ));
        }
        Ok(())
    }

    /// A durable rail result, or cancellation before any authorization, proves
    /// that this payment no longer exposes funds for pre-dispatch compensation.
    #[must_use]
    pub fn is_compensated_before_dispatch(&self) -> bool {
        if self.validate().is_err() {
            return false;
        }
        let cancelled =
            self.state == PaymentJournalState::Closed && self.authorization_id.is_none();
        let no_effect = self.release_authority.as_ref().is_some_and(|authority| {
            authority.kind == PaymentReleaseAuthorityKind::PreDispatchNoEffect
        });
        let released = self.rail_mode == PaymentRailMode::ReversibleHold
            && self.state == PaymentJournalState::Settled
            && self.settle_action == Some(PaymentSettleAction::Release)
            && no_effect;
        let refunded = self.rail_mode == PaymentRailMode::PrepaidFinal
            && self.state == PaymentJournalState::Closed
            && self.transaction_id.is_some()
            && no_effect;
        cancelled || released || refunded
    }
}
