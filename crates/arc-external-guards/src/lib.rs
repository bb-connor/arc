//! HTTP-backed external guard adapters.
//!
//! This crate hosts the concrete cloud guardrail and threat-intel guards that
//! need an HTTP transport dependency. The generic async adapter, retry,
//! caching, and circuit-breaker infrastructure remains in `arc-guards`.

use std::future::Future;

use arc_kernel::{Guard, GuardContext, KernelError, Verdict};

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

/// Synchronous kernel bridge for an async external guard adapter.
///
/// The kernel guard pipeline is synchronous today, so this wrapper executes the
/// async adapter on a Tokio runtime and optionally scopes the guard to a subset
/// of tool-name patterns.
pub struct ScopedAsyncGuard<E: ExternalGuard> {
    adapter: AsyncGuardAdapter<E>,
    tool_patterns: Vec<String>,
}

impl<E: ExternalGuard> ScopedAsyncGuard<E> {
    /// Wrap an async adapter for the kernel guard pipeline.
    pub fn new(adapter: AsyncGuardAdapter<E>, tool_patterns: Vec<String>) -> Self {
        Self {
            adapter,
            tool_patterns,
        }
    }

    fn matches_tool(&self, tool_name: &str) -> bool {
        self.tool_patterns.is_empty()
            || self
                .tool_patterns
                .iter()
                .any(|pattern| wildcard_matches(pattern, tool_name))
    }

    fn call_context(&self, ctx: &GuardContext<'_>) -> GuardCallContext {
        GuardCallContext {
            tool_name: ctx.request.tool_name.clone(),
            agent_id: ctx.agent_id.clone(),
            server_id: ctx.server_id.clone(),
            arguments_json: ctx.request.arguments.to_string(),
        }
    }

    fn block_on<T>(&self, future: impl Future<Output = T>) -> Result<T, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    Ok(tokio::task::block_in_place(|| handle.block_on(future)))
                }
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(KernelError::GuardDenied(format!(
                        "external guard {} requires a multithreaded Tokio runtime",
                        self.name()
                    )))
                }
                flavor => Err(KernelError::GuardDenied(format!(
                    "external guard {} cannot run on Tokio runtime flavor {flavor:?}",
                    self.name()
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::GuardDenied(format!(
                        "external guard {} could not start a runtime: {error}",
                        self.name()
                    ))
                })
                .map(|runtime| runtime.block_on(future)),
        }
    }
}

impl<E: ExternalGuard> Guard for ScopedAsyncGuard<E> {
    fn name(&self) -> &str {
        self.adapter.name()
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        if !self.matches_tool(&ctx.request.tool_name) {
            return Ok(Verdict::Allow);
        }

        let call_ctx = self.call_context(ctx);
        self.block_on(self.adapter.evaluate(&call_ctx))
    }
}

fn wildcard_matches(pattern: &str, target: &str) -> bool {
    let pattern = pattern.as_bytes();
    let target = target.as_bytes();
    let mut pattern_index = 0usize;
    let mut target_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut match_index = 0usize;

    while target_index < target.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == target[target_index])
        {
            pattern_index += 1;
            target_index += 1;
            continue;
        }
        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            match_index = target_index;
            continue;
        }
        if let Some(star) = star_index {
            pattern_index = star + 1;
            match_index += 1;
            target_index = match_index;
            continue;
        }
        return false;
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}
