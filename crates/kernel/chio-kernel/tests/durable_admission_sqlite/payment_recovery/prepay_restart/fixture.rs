use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode,
};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct PrepayFacts {
    pub(super) calls: Arc<PaymentCalls>,
    pub(super) original_authorizations: Mutex<Vec<(String, u64, String)>>,
}

pub(super) struct ExactPrepayRail(pub(super) Arc<PrepayFacts>);
impl PaymentAdapter for ExactPrepayRail {
    fn rail_id(&self) -> &'static str {
        "sqlite-test-prepaid-final"
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.0
            .original_authorizations
            .lock()
            .map_err(|_| PaymentError::Unavailable("test trace lock".into()))?
            .push((
                request.reference.clone(),
                request.amount_units,
                request.currency.clone(),
            ));
        PrepaidFinalPaymentAdapter {
            calls: self.0.calls.clone(),
        }
        .authorize(request)
    }
    fn capture(
        &self,
        authorization: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        PrepaidFinalPaymentAdapter {
            calls: self.0.calls.clone(),
        }
        .capture(authorization, amount, currency, reference)
    }
    fn release(&self, authorization: &str, reference: &str) -> Result<PaymentResult, PaymentError> {
        PrepaidFinalPaymentAdapter {
            calls: self.0.calls.clone(),
        }
        .release(authorization, reference)
    }
    fn refund(
        &self,
        transaction: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        PrepaidFinalPaymentAdapter {
            calls: self.0.calls.clone(),
        }
        .refund(transaction, amount, currency, reference)
    }
}

pub(super) fn scope_with_original_quote() -> ChioScope {
    let mut result = paid_scope();
    if let Some(grant) = result.grants.first_mut() {
        grant.constraints = vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove { threshold_units: 4 },
        ];
    }
    result
}

pub(super) fn attach_original_quote(
    kernel: &ChioKernel,
    request: &mut ToolCallRequest,
    approver: &Keypair,
    at: u64,
) -> Result<(), Box<dyn Error>> {
    let mut intent = GovernedTransactionIntent {
        id: "sqlite-exact-prepaid-intent".into(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "prepaid restart control".into(),
        max_amount: Some(MonetaryAmount {
            units: 10,
            currency: "USD".into(),
        }),
        commerce: None,
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: "sqlite-original-five-unit-quote".into(),
                provider: "sqlite-prepay-test".into(),
                billing_unit: "invocation".into(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units: 5,
                    currency: "USD".into(),
                },
                issued_at: at,
                expires_at: Some(at.checked_add(300).ok_or("quote expiry")?),
            },
            max_billed_units: Some(1),
            verified_outcome: None,
        }),
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    chio_kernel::approval::ToolApprovalContext::bind(
        &mut intent,
        &request.capability,
        &request.arguments,
        &request.request_id,
        kernel.policy_hash(),
        "sqlite-exact-prepay-tenant",
    )?;
    request.approval_token = Some(GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "sqlite-exact-prepay-approval".into(),
            approver: approver.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent.binding_hash()?,
            request_id: request.request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: at,
            expires_at: at.checked_add(300).ok_or("approval expiry")?,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )?);
    request.governed_intent = Some(intent);
    Ok(())
}
