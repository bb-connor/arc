//! HTTP-backed external guard adapters.
//!
//! This crate hosts the concrete cloud guardrail and threat-intel guards that
//! need an HTTP transport dependency. The generic async adapter, retry,
//! caching, and circuit-breaker infrastructure remains in `arc-guards`.

pub mod external;

pub use external::{
    retry_with_jitter, retry_with_jitter_rng, AsyncGuardAdapter, AsyncGuardAdapterBuilder,
    AsyncGuardAdapterConfig, AzureCategory, AzureCategoryBreakdown, AzureContentSafetyConfig,
    AzureContentSafetyGuard, AzureDecisionDetails, BackoffStrategy, BedrockDecisionDetails,
    BedrockGuardrailConfig, BedrockGuardrailGuard, BedrockSource, CircuitBreaker,
    CircuitBreakerConfig, CircuitOpenVerdict, CircuitState, Clock, ExternalGuard,
    ExternalGuardError, GuardCallContext, RateLimitedVerdict, RetryConfig, SafeBrowsingConfig,
    SafeBrowsingGuard, SnykConfig, SnykGuard, SnykSeverity, TokenBucket, TokioClock, TtlCache,
    VertexDecisionDetails, VertexProbability, VertexRatingBreakdown, VertexSafetyConfig,
    VertexSafetyGuard, VirusTotalConfig, VirusTotalGuard,
};
