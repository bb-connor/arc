//! CLI selection of the kernel payment adapter. Sim is the safe default; the
//! http variants delegate to an external facilitator. No custody or broadcast
//! variant is exposed (custody-neutral).

use chio_kernel::payment::SimPaymentAdapter;
use chio_kernel::{AcpPaymentAdapter, PaymentAdapter, X402PaymentAdapter};

#[derive(Debug, Clone)]
pub enum PaymentAdapterConfig {
    Sim,
    HttpX402 {
        base_url: String,
        bearer_token: Option<String>,
    },
    HttpAcp {
        base_url: String,
        bearer_token: Option<String>,
    },
}

impl PaymentAdapterConfig {
    #[must_use]
    pub fn default_safe() -> Self {
        Self::Sim
    }

    /// Read the payment adapter config from environment variables.
    ///
    /// `CHIO_PAYMENT_ADAPTER`: `sim` (default), `http-x402`, `http-acp`.
    /// `CHIO_PAYMENT_BASE_URL`: required when the adapter is `http-x402` or `http-acp`.
    /// `CHIO_PAYMENT_BEARER_TOKEN`: optional bearer token for http adapters.
    ///
    /// Returns `Ok(None)` when `CHIO_PAYMENT_ADAPTER` is absent or set to `sim`
    /// (the caller then uses the documented default). Returns `Err` when the
    /// variable is present but its value is not a recognized adapter kind -
    /// an unrecognized value would otherwise silently mask a misconfigured
    /// real payment rail.
    pub fn from_env() -> Result<Option<Self>, String> {
        let kind = match std::env::var("CHIO_PAYMENT_ADAPTER") {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let base_url = std::env::var("CHIO_PAYMENT_BASE_URL").unwrap_or_default();
        let bearer_token = std::env::var("CHIO_PAYMENT_BEARER_TOKEN").ok();
        match kind.as_str() {
            "sim" | "" => Ok(None),
            "http-x402" => Ok(Some(Self::HttpX402 {
                base_url,
                bearer_token,
            })),
            "http-acp" => Ok(Some(Self::HttpAcp {
                base_url,
                bearer_token,
            })),
            other => Err(format!(
                "CHIO_PAYMENT_ADAPTER: unrecognized adapter kind {:?}; \
                 expected one of: sim, http-x402, http-acp",
                other
            )),
        }
    }

    /// Load-time config-consistency check (house rule: invalid policies reject
    /// at load time). This is a config-shape check only; the authoritative
    /// fail-closed enforcement is the kernel runtime MustPrepay gate.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Sim => Ok(()),
            Self::HttpX402 { base_url, .. } | Self::HttpAcp { base_url, .. } => {
                if base_url.trim().is_empty() {
                    return Err("http payment adapter requires a non-empty base_url".to_string());
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn build_adapter(&self) -> Box<dyn PaymentAdapter> {
        match self {
            Self::Sim => Box::new(SimPaymentAdapter::new()),
            Self::HttpX402 {
                base_url,
                bearer_token,
            } => {
                let mut adapter = X402PaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
            Self::HttpAcp {
                base_url,
                bearer_token,
            } => {
                let mut adapter = AcpPaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn default_is_sim_and_safe() {
        assert!(matches!(
            PaymentAdapterConfig::default_safe(),
            PaymentAdapterConfig::Sim
        ));
    }

    #[test]
    fn unknown_adapter_kind_errors_at_load_time_not_silently_downgrades() {
        // A present-but-unrecognized CHIO_PAYMENT_ADAPTER must produce an error,
        // not silently fall back to Sim. This prevents a misconfigured real rail
        // from being masked by a silent default.
        std::env::set_var("CHIO_PAYMENT_ADAPTER", "mystery-rail");
        let result = PaymentAdapterConfig::from_env();
        std::env::remove_var("CHIO_PAYMENT_ADAPTER");
        let error = result.test_expect_err("unknown adapter kind must fail at load time");
        assert!(
            error.contains("mystery-rail") && error.contains("unrecognized"),
            "error must identify the unknown kind: {error}"
        );
    }

    #[test]
    fn http_x402_requires_non_empty_base_url() {
        let cfg = PaymentAdapterConfig::HttpX402 {
            base_url: "   ".to_string(),
            bearer_token: None,
        };
        let error = cfg
            .validate()
            .test_expect_err("blank base_url must reject at load time");
        assert!(error.contains("base_url"));
    }

    #[test]
    fn valid_variants_pass_validation_and_build() {
        let sim = PaymentAdapterConfig::Sim;
        sim.validate().test_unwrap();
        let _ = sim.build_adapter();
        let http = PaymentAdapterConfig::HttpAcp {
            base_url: "https://facilitator.example".to_string(),
            bearer_token: Some("tok".to_string()),
        };
        http.validate().test_unwrap();
        let _ = http.build_adapter();
    }
}
