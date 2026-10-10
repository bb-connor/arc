use super::*;

pub(super) struct ReportedCostServer {
    pub(super) units: u64,
    pub(super) currency: &'static str,
    pub(super) invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for ReportedCostServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"paid_output": true}))
    }
    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let output = self.invoke(tool_name, arguments, bridge).await?;
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

pub(super) struct MovingOracle {
    pub(super) rate: Arc<AtomicU64>,
    pub(super) calls: Arc<AtomicU64>,
}

impl PriceOracle for MovingOracle {
    fn get_rate<'a>(&'a self, base: &'a str, quote: &'a str) -> chio_link::OracleFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let now = current_unix_timestamp_ms() / 1_000;
        let rate = ExchangeRate {
            base: base.into(),
            quote: quote.into(),
            rate_numerator: u128::from(self.rate.load(Ordering::SeqCst)),
            rate_denominator: 1,
            updated_at: now,
            fetched_at: now,
            source: "review-oracle".into(),
            feed_reference: "original-rate".into(),
            max_age_seconds: 600,
            conversion_margin_bps: 0,
            confidence_numerator: None,
            confidence_denominator: None,
        };
        Box::pin(async move { Ok(rate) })
    }
    fn supported_pairs(&self) -> Vec<String> {
        vec!["ETH/USD".into()]
    }
}
