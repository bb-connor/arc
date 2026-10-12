//! Synchronous price oracle reads and cross-currency cost conversion.
use super::*;

impl ChioKernel {
    fn block_on_price_oracle<T>(
        &self,
        future: impl Future<Output = Result<T, PriceOracleError>>,
    ) -> Result<T, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle
                        .block_on(future)
                        .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))
                }),
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(KernelError::CrossCurrencyOracle(
                        "current-thread tokio runtime cannot synchronously resolve price oracles"
                            .to_string(),
                    ))
                }
                flavor => Err(KernelError::CrossCurrencyOracle(format!(
                    "unsupported tokio runtime flavor for synchronous oracle resolution: {flavor:?}"
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::CrossCurrencyOracle(format!(
                        "failed to build synchronous oracle runtime: {error}"
                    ))
                })?
                .block_on(future)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string())),
        }
    }

    pub(crate) fn resolve_cross_currency_cost(
        &self,
        reported_cost: &ToolInvocationCost,
        grant_currency: &str,
        timestamp: u64,
    ) -> Result<(u64, chio_core::web3::anchors::OracleConversionEvidence), KernelError> {
        let rate = self.fetch_cross_currency_rate(&reported_cost.currency, grant_currency)?;
        // Oracle I/O may advance time beyond the caller's trusted reading.
        let timestamp = self.trusted_now_millis()?.as_secs().max(timestamp);
        Self::convert_cross_currency_cost(reported_cost, grant_currency, &rate, timestamp)
    }

    pub(crate) fn fetch_cross_currency_rate(
        &self,
        base: &str,
        quote: &str,
    ) -> Result<chio_link::ExchangeRate, KernelError> {
        let oracle =
            self.price_oracle
                .as_ref()
                .ok_or_else(|| KernelError::NoCrossCurrencyOracle {
                    base: base.to_string(),
                    quote: quote.to_string(),
                })?;
        self.block_on_price_oracle(oracle.get_rate(base, quote))
    }

    /// `timestamp` is the trusted time the quote's freshness is checked at.
    pub(crate) fn convert_cross_currency_cost(
        reported_cost: &ToolInvocationCost,
        grant_currency: &str,
        rate: &chio_link::ExchangeRate,
        timestamp: u64,
    ) -> Result<(u64, chio_core::web3::anchors::OracleConversionEvidence), KernelError> {
        let converted_units =
            convert_supported_units(reported_cost.units, rate, rate.conversion_margin_bps)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        let evidence = rate
            .to_conversion_evidence(
                reported_cost.units,
                reported_cost.currency.clone(),
                grant_currency.to_string(),
                converted_units,
                timestamp,
            )
            .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        Ok((converted_units, evidence))
    }
}
