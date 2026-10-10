//! Security guards for the Chio runtime kernel.
//!
//! This crate provides policy-driven security guards.  Each guard
//! implements `chio_kernel::Guard` and can be registered on the kernel via
//! `kernel.add_guard(...)` or composed into a [`GuardPipeline`].
//!
//! # Implemented guards
//!
//! | Guard | Status | Description |
//! |-------|--------|-------------|
//! | [`ForbiddenPathGuard`] | **Full** | Blocks access to sensitive filesystem paths |
//! | [`ShellCommandGuard`] | **Full** | Blocks dangerous shell commands |
//! | [`EgressAllowlistGuard`] | **Full** | Controls network egress by domain |
//! | [`PathAllowlistGuard`] | **Full** | Allowlist-based path access control |
//! | [`McpToolGuard`] | **Full** | Restricts MCP tool invocations |
//! | [`SecretLeakGuard`] | **Full** | Detects secrets in file writes |
//! | [`PatchIntegrityGuard`] | **Full** | Validates patch safety |
//! | [`InternalNetworkGuard`] | **Full** | Blocks SSRF targeting private/reserved addresses |
//! | [`AgentVelocityGuard`] | **Full** | Per-agent and per-session rate limiting |
//! | [`DataFlowGuard`] | **Full** | Cumulative bytes-read/written limits via session journal |
//! | [`BehavioralSequenceGuard`] | **Full** | Tool ordering policies via session journal |
//! | [`ResponseSanitizationGuard`] | **Full** | PII/PHI pattern detection and redaction |
//! | [`AdvisoryPipeline`] | **Full** | Non-blocking advisory signals with optional promotion |
//! | [`AnomalyAdvisoryGuard`] | **Full** | Flags unusual invocation patterns and delegation depth |
//! | [`DataTransferAdvisoryGuard`] | **Full** | Flags high data transfer volumes |
//! | [`JailbreakGuard`] | **Full** | Multi-layer jailbreak detection (heuristic + statistical + ML) |
//!
//! # Guard pipeline
//!
//! The [`GuardPipeline`] runs guards in sequence, fail-closed.  If any guard
//! denies, the pipeline denies.  Register it on the kernel:
//!
//! ```ignore
//! use chio_guards::GuardPipeline;
//!
//! let pipeline = GuardPipeline::default_pipeline();
//! kernel.add_guard(Box::new(pipeline));
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod action;
mod path_normalization;

pub mod external;
mod input;

pub mod advisory;
pub mod agent_velocity;
pub mod behavioral_profile;
pub mod behavioral_sequence;
pub mod data_flow;
mod egress_allowlist;
mod forbidden_path;
pub mod internal_network;
pub mod jailbreak;
pub mod jailbreak_detector;
pub mod mcp_tool;
pub mod patch_integrity;
pub mod path_allowlist;
mod pipeline;
pub mod post_invocation;
pub mod prompt_injection;
pub mod response_sanitization;
pub mod secret_leak;
mod shell_command;
pub mod text_utils;
pub mod velocity;

// Computer Use Agent (CUA) and EmbeddingAnomaly guards.
pub mod computer_use;
pub mod embedding_anomaly;
pub mod input_injection;
pub mod remote_desktop;

// Code execution, browser automation, content review, and memory
// governance guards.
pub mod browser_automation;
pub mod code_execution;
pub mod content_review;
pub mod finding_retraction;
pub mod memory_governance;

pub use advisory::{
    AdvisoryGuard, AdvisoryPipeline, AdvisorySeverity, AdvisorySignal, AnomalyAdvisoryGuard,
    DataTransferAdvisoryGuard, GuardOutput, PromotionPolicy, PromotionRule,
};
pub use agent_velocity::{AgentVelocityConfig, AgentVelocityGuard};
pub use behavioral_profile::{
    BehavioralMetric, BehavioralProfileConfig, BehavioralProfileGuard, InMemoryReceiptFeed,
    ObservationOutcome, ReceiptFeedSource, DEFAULT_BASELINE_MIN_WINDOWS, DEFAULT_EMA_ALPHA,
    DEFAULT_SIGMA_THRESHOLD, DEFAULT_WINDOW_SECS,
};
pub use behavioral_sequence::{BehavioralSequenceGuard, SequencePolicy};
pub use data_flow::{DataFlowConfig, DataFlowGuard};
pub use egress_allowlist::EgressAllowlistGuard;
pub use forbidden_path::{ForbiddenPathConfigError, ForbiddenPathGuard};
pub use internal_network::InternalNetworkGuard;
pub use jailbreak::{
    JailbreakGuard, JailbreakGuardConfig,
    DEFAULT_FINGERPRINT_CAPACITY as JAILBREAK_DEFAULT_FINGERPRINT_CAPACITY,
};
pub use jailbreak_detector::{
    Detection as JailbreakDetection, DetectorConfig as JailbreakDetectorConfig, JailbreakCategory,
    JailbreakDetector, LayerScores as JailbreakLayerScores, LayerWeights,
    LinearModel as JailbreakLinearModel, Signal as JailbreakSignal,
    StatisticalThresholds as JailbreakStatisticalThresholds,
    DEFAULT_DENY_THRESHOLD as JAILBREAK_DEFAULT_DENY_THRESHOLD,
};
pub use mcp_tool::McpToolGuard;
pub use patch_integrity::PatchIntegrityGuard;
pub use path_allowlist::PathAllowlistGuard;
pub use pipeline::GuardPipeline;
pub use post_invocation::{
    sanitize_json, PipelineOutcome, PostInvocationHook, PostInvocationHookIdentity,
    PostInvocationPipeline, PostInvocationVerdict, SanitizerHook,
};
pub use prompt_injection::{
    Detection as PromptInjectionDetection, PromptInjectionConfig, PromptInjectionGuard,
    Signal as PromptInjectionSignal,
};
pub use response_sanitization::{
    AllowlistConfig, CategoryConfig, DenylistConfig, EntropyConfig, OutputSanitizer,
    OutputSanitizerConfig, OutputSanitizerConfigError, ProcessingStats, Redaction,
    RedactionStrategy, ResponseSanitizationGuard, SanitizationAction, SanitizationResult,
    SanitizedValue, ScanResult, SensitiveCategory, SensitiveDataFinding, SensitivityLevel, Span,
    TokenVault,
};
pub use secret_leak::SecretLeakGuard;
pub use shell_command::{ShellCommandConfigError, ShellCommandGuard};
pub use velocity::VelocityGuard;

pub use action::{extract_action, extract_action_checked, MalformedAction, ToolAction};

pub use external::{
    AsyncGuardAdapter, AsyncGuardAdapterBuilder, AsyncGuardAdapterConfig, CircuitBreaker,
    CircuitBreakerConfig, CircuitOpenVerdict, CircuitState, ExternalGuard, ExternalGuardError,
    GuardCallContext, RateLimitedVerdict, RetryConfig, TokenBucket, TtlCache,
};

fn revalidate_non_consuming_guard(
    guard: &(impl chio_kernel::Guard + ?Sized),
    ctx: &chio_kernel::GuardContext<'_>,
) -> Result<(), chio_kernel::KernelError> {
    match guard.evaluate(ctx)?.verdict {
        chio_kernel::Verdict::Allow => Ok(()),
        // Admission owns approval adjudication. A pure re-evaluation may still
        // describe the original threshold as pending, but must not turn an
        // already-adjudicated request into a hard denial at dispatch.
        chio_kernel::Verdict::PendingApproval => Ok(()),
        chio_kernel::Verdict::Deny => Err(chio_kernel::KernelError::GuardDenied(
            "guard dispatch revalidation denied".to_string(),
        )),
    }
}

/// Default guard material installed by the control-plane runtime profile.
pub struct RuntimeGuardProfile {
    pub pre_invocation_guards: Vec<Box<dyn chio_kernel::Guard>>,
    pub post_invocation_pipeline: PostInvocationPipeline,
}

/// Build the default Chio runtime guard profile without coupling the kernel to
/// concrete guard implementations.
pub fn default_runtime_guard_profile() -> RuntimeGuardProfile {
    DefaultRuntimeGuardMaterial::new().into_profile()
}

/// Canonical identity of the exact defaults installed by
/// [`default_runtime_guard_profile`]. Component versions name the enforcement
/// algorithms; the material binds their actual parameters and sanitizer config.
/// Velocity thresholds and the advisory detector roster are empty by default.
pub fn default_runtime_guard_profile_identity() -> Result<String, chio_core::Error> {
    DefaultRuntimeGuardMaterial::new().identity()
}

// Keep construction and identity on the same inputs. A change to an enforcement
// algorithm also requires a component-version change in the identity material.
struct DefaultRuntimeGuardMaterial {
    extra_blocked_hosts: Vec<String>,
    dns_rebinding_detection: bool,
    velocity: AgentVelocityConfig,
    velocity_bucket_cap: usize,
    advisory_policy: PromotionPolicy,
    sanitizer: SanitizerHook,
}

impl DefaultRuntimeGuardMaterial {
    fn new() -> Self {
        Self {
            extra_blocked_hosts: Vec::new(),
            dns_rebinding_detection: true,
            velocity: AgentVelocityConfig::default(),
            velocity_bucket_cap: chio_kernel::MemoryBudgetConfig::defaults()
                .velocity_bucket_cap
                .max(1),
            advisory_policy: PromotionPolicy::new(),
            sanitizer: SanitizerHook::new(),
        }
    }

    fn identity(&self) -> Result<String, chio_core::Error> {
        let AgentVelocityConfig {
            max_requests_per_agent,
            max_requests_per_session,
            window_secs,
            burst_factor,
        } = &self.velocity;
        if !burst_factor.is_finite() {
            return Err(chio_core::Error::CanonicalJson(
                "default guard identity requires finite velocity parameters".into(),
            ));
        }
        let sanitizer = self
            .sanitizer
            .durable_identity()
            .map_err(chio_core::Error::CanonicalJson)?
            .ok_or_else(|| {
                chio_core::Error::CanonicalJson(
                    "default sanitizer requires a deterministic hook identity".into(),
                )
            })?;
        let guards = self.pre_invocation_guards();
        let guard_order: Vec<&str> = guards.iter().map(|guard| guard.name()).collect();
        let material = serde_json::json!({
            "schema": "chio.default-runtime-guard-profile.v1",
            "pre_invocation_order": guard_order,
            "guard_configurations": [
                {
                    "component": "chio-guards.internal-network.v1",
                    "config": {
                        "extra_blocked_hosts": self.extra_blocked_hosts,
                        "dns_rebinding_detection": self.dns_rebinding_detection,
                    },
                },
                {
                    "component": "chio-guards.agent-velocity.v1",
                    "config": {
                        "max_requests_per_agent": max_requests_per_agent,
                        "max_requests_per_session": max_requests_per_session,
                        "window_secs": window_secs,
                        "burst_factor": burst_factor,
                        "bucket_cap": self.velocity_bucket_cap,
                    },
                },
                {
                    "component": "chio-guards.advisory-pipeline.v1",
                    // AdvisoryPipeline::new installs no detectors. Registering
                    // defaults here requires their configuration in this material.
                    "config": { "detectors": [], "promotion_policy": self.advisory_policy },
                },
            ],
            "post_invocation": [sanitizer],
        });
        let bytes = chio_core::canonical::canonical_json_bytes(&material)?;
        Ok(chio_core::sha256_hex(&bytes))
    }

    fn pre_invocation_guards(&self) -> Vec<Box<dyn chio_kernel::Guard>> {
        vec![
            Box::new(InternalNetworkGuard::with_config(
                self.extra_blocked_hosts.clone(),
                self.dns_rebinding_detection,
            )),
            Box::new(AgentVelocityGuard::with_bucket_cap(
                self.velocity.clone(),
                self.velocity_bucket_cap,
            )),
            Box::new(AdvisoryPipeline::new(self.advisory_policy.clone())),
        ]
    }

    fn into_profile(self) -> RuntimeGuardProfile {
        let pre_invocation_guards = self.pre_invocation_guards();
        let mut post_invocation_pipeline = PostInvocationPipeline::new();
        post_invocation_pipeline.add(Box::new(self.sanitizer));

        RuntimeGuardProfile {
            pre_invocation_guards,
            post_invocation_pipeline,
        }
    }
}

// Computer Use Agent (CUA) and EmbeddingAnomaly re-exports.
pub use computer_use::{
    default_allowed_action_types as computer_use_default_allowed_action_types, ComputerUseConfig,
    ComputerUseGuard, EnforcementMode,
};
pub use embedding_anomaly::{
    cosine_similarity as embedding_anomaly_cosine_similarity, extract_embedding, AmbiguousPolicy,
    EmbeddingAnomalyConfig, EmbeddingAnomalyError, EmbeddingAnomalyGuard,
    EmbeddingAnomalyPatternDb, PatternEntry, DEFAULT_AMBIGUITY_BAND, DEFAULT_SIMILARITY_THRESHOLD,
    DEFAULT_TOP_K,
};
pub use input_injection::{
    default_allowed_input_types, InputInjectionCapabilityConfig, InputInjectionCapabilityGuard,
};
pub use remote_desktop::{RemoteDesktopSideChannelConfig, RemoteDesktopSideChannelGuard};

// Code execution, browser automation, content review, and memory
// governance re-exports.
pub use browser_automation::{
    default_allowed_verbs as browser_automation_default_allowed_verbs, BrowserAutomationConfig,
    BrowserAutomationError, BrowserAutomationGuard,
};
pub use code_execution::{
    default_dangerous_modules as code_execution_default_dangerous_modules, CodeExecutionConfig,
    CodeExecutionError, CodeExecutionGuard,
};
pub use content_review::{
    ContentReviewConfig, ContentReviewError, ContentReviewGuard, ContentReviewRules,
};
pub use finding_retraction::{
    AuthenticatedFindingStatus, Clock, FindingDeliveryLineageResolver, FindingRetractionQuery,
    FindingRetractionResolution, FindingRetractionResolveError, FindingRetractionResolver,
    FindingStatusCache, FindingStatusValue, VerifiedFindingDeliveryLineage,
    VerifiedFindingRetractionResolver, FINDING_RETRACTION_RESOLVER_PROFILE,
};
pub use memory_governance::{
    FindingRetractionGuardConfig, MemoryGovernanceConfig, MemoryGovernanceError,
    MemoryGovernanceGuard,
};

#[cfg(test)]
mod runtime_guard_profile_tests {
    use super::*;

    #[test]
    fn product_default_guards_identity_binds_actual_factory_parameters(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let baseline = default_runtime_guard_profile_identity()?;
        assert_eq!(baseline.len(), 64);
        assert_eq!(baseline, default_runtime_guard_profile_identity()?);
        let changes: [fn(&mut DefaultRuntimeGuardMaterial); 8] = [
            |material| material.extra_blocked_hosts.push("blocked.example".into()),
            |material| material.dns_rebinding_detection = false,
            |material| material.velocity.max_requests_per_agent = Some(1),
            |material| material.velocity.max_requests_per_session = Some(1),
            |material| material.velocity.window_secs += 1,
            |material| material.velocity.burst_factor += 1.0,
            |material| material.velocity_bucket_cap += 1,
            |material| {
                material.advisory_policy.add_rule(PromotionRule {
                    guard_name: "configured-advisory".into(),
                    min_severity: AdvisorySeverity::High,
                })
            },
        ];
        for (index, change) in changes.into_iter().enumerate() {
            let mut material = DefaultRuntimeGuardMaterial::new();
            change(&mut material);
            assert_ne!(baseline, material.identity()?, "unbound parameter {index}");
        }
        let mut material = DefaultRuntimeGuardMaterial::new();
        let mut sanitizer = material.sanitizer.sanitizer().config().clone();
        sanitizer.max_input_bytes -= 1;
        material.sanitizer = SanitizerHook::with_config(sanitizer)?;
        assert_ne!(baseline, material.identity()?);
        material.velocity.burst_factor = f64::NAN;
        assert!(material.identity().is_err());
        Ok(())
    }
}
