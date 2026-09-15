use crate::common;
use chio_kernel::payment::*;
use chio_store_sqlite::SqliteFindingOperatorPaymentAdapter;

/// A harness-only fault at the native rail's commit/acknowledgement boundary.
pub struct CrashAfterPayment(
    pub SqliteFindingOperatorPaymentAdapter,
    pub PaymentSettleAction,
);
impl PaymentAdapter for CrashAfterPayment {
    fn rail_id(&self) -> &'static str {
        self.0.rail_id()
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.0.rail_mode()
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.0.authorize(request)
    }
    fn capture(
        &self,
        id: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let committed = self.0.capture(id, amount, currency, reference)?;
        if self.1 == PaymentSettleAction::Capture {
            common::crash().map_err(|e| PaymentError::RailError(e.to_string()))?;
        }
        Ok(committed)
    }
    fn release(&self, id: &str, reference: &str) -> Result<PaymentResult, PaymentError> {
        let committed = self.0.release(id, reference)?;
        if self.1 == PaymentSettleAction::Release {
            common::crash().map_err(|e| PaymentError::RailError(e.to_string()))?;
        }
        Ok(committed)
    }
    fn refund(
        &self,
        id: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.0.refund(id, amount, currency, reference)
    }
    fn settlement_state(
        &self,
        reference: &str,
        id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.0.settlement_state(reference, id)
    }
}
