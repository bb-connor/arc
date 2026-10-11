use super::*;

pub(super) struct LostPaymentAcknowledgement {
    pub(super) adapter: QualifiedDurablePaymentAdapter,
    pub(super) boundary: FailureBoundary,
}

impl PaymentAdapter for LostPaymentAcknowledgement {
    fn rail_id(&self) -> &'static str {
        self.adapter.rail_id()
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.adapter.rail_mode()
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let authorization = self.adapter.authorize(request)?;
        if matches!(self.boundary, FailureBoundary::AuthorizationAcknowledgement) {
            Err(PaymentError::Unavailable(
                "authorization acknowledgement lost".into(),
            ))
        } else {
            Ok(authorization)
        }
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.adapter
            .capture(authorization_id, amount_units, currency, reference)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let release = self.adapter.release(authorization_id, reference)?;
        if matches!(self.boundary, FailureBoundary::UnwindAcknowledgement) {
            Err(PaymentError::Unavailable(
                "release acknowledgement lost".into(),
            ))
        } else {
            Ok(release)
        }
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.adapter
            .refund(transaction_id, amount_units, currency, reference)
    }
}
