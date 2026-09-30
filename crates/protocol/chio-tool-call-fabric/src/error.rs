use thiserror::Error;

#[derive(Error)]
pub enum ProviderError {
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Invocation(#[from] crate::ToolInvocationValidationError),
    #[error("urn:chio:error:transport:http-failed")]
    Transport {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("urn:chio:error:transport:stream-capacity-exceeded")]
    StreamCapacityExceeded,
    #[error("{code}", code = .0.code())]
    Clock(#[from] chio_security_types::clock::ClockError),
    /// Peer JSON rejection. The local parser cause is retained; Display is redacted.
    #[error("{0}")]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
    #[error("rate limited by upstream: retry after {retry_after_ms}ms")]
    RateLimited {
        retry_after_ms: u64,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error("upstream content policy denied request: {0}")]
    ContentPolicy(String),
    #[error("tool arguments failed schema validation: {0}")]
    BadToolArgs(String),
    #[error("upstream service failure ({status})")]
    Upstream5xx {
        status: u16,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error("transport timeout after {ms}ms")]
    TransportTimeout {
        ms: u64,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error("verdict latency budget exceeded ({observed_ms}ms > {budget_ms}ms); fail-closed")]
    VerdictBudgetExceeded { observed_ms: u64, budget_ms: u64 },
    #[error("malformed upstream payload: {0}")]
    Malformed(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl std::fmt::Debug for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
