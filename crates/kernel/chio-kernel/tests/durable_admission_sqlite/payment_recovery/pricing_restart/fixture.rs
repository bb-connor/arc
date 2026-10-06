use super::*;
use chio_link::{ExchangeRate, PriceOracle};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct PricingFacts {
    pub(super) calls: Arc<PaymentCalls>,
    pub(super) captures: Mutex<Vec<(String, u64, String)>>,
    pub(super) oracle_calls: AtomicU64,
    pub(super) rate: AtomicU64,
}

pub(super) struct MovingRate(pub(super) Arc<PricingFacts>);
impl PriceOracle for MovingRate {
    fn get_rate<'a>(&'a self, base: &'a str, quote: &'a str) -> chio_link::OracleFuture<'a> {
        self.0.oracle_calls.fetch_add(1, Ordering::SeqCst);
        let at = chio_test_support::clock::unix_seconds();
        let result = ExchangeRate {
            base: base.into(),
            quote: quote.into(),
            rate_numerator: u128::from(self.0.rate.load(Ordering::SeqCst)),
            rate_denominator: 1,
            updated_at: at,
            fetched_at: at,
            source: "sqlite-restart-oracle".into(),
            feed_reference: "original-retained-rate".into(),
            max_age_seconds: 600,
            conversion_margin_bps: 0,
            confidence_numerator: None,
            confidence_denominator: None,
        };
        Box::pin(async move { Ok(result) })
    }
    fn supported_pairs(&self) -> Vec<String> {
        vec!["ETH/USD".into()]
    }
}

pub(super) struct TracedCapture(pub(super) Arc<PricingFacts>);
impl PaymentAdapter for TracedCapture {
    fn rail_id(&self) -> &'static str {
        "sqlite-test-reversible"
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        ReversiblePaymentAdapter {
            calls: Some(self.0.calls.clone()),
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
        self.0
            .captures
            .lock()
            .map_err(|_| PaymentError::Unavailable("capture trace lock".into()))?
            .push((reference.into(), amount, currency.into()));
        ReversiblePaymentAdapter {
            calls: Some(self.0.calls.clone()),
        }
        .capture(authorization, amount, currency, reference)
    }
    fn release(&self, authorization: &str, reference: &str) -> Result<PaymentResult, PaymentError> {
        ReversiblePaymentAdapter {
            calls: Some(self.0.calls.clone()),
        }
        .release(authorization, reference)
    }
    fn refund(
        &self,
        _transaction: &str,
        _amount: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.0.calls.refunds.fetch_add(1, Ordering::SeqCst);
        Err(PaymentError::RailError(
            "returned capture fixture has no refund authority".into(),
        ))
    }
}

pub(super) struct CostServer {
    pub(super) invocations: Arc<AtomicU64>,
    pub(super) units: u64,
    pub(super) currency: &'static str,
}
#[async_trait::async_trait]
impl ToolServerConnection for CostServer {
    fn server_id(&self) -> &str {
        "sqlite-durable-paid-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"original_paid_output": true}))
    }
    async fn invoke_with_cost(
        &self,
        name: &str,
        args: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let output = self.invoke(name, args, bridge).await?;
        Ok((
            output,
            Some(ToolInvocationCost {
                units: self.units,
                currency: self.currency.into(),
                breakdown: None,
            }),
        ))
    }
}
