//! Security guards for the ARC runtime kernel.
//!
//! This crate provides policy-driven security guards adapted from
//! [ClawdStrike](https://github.com/backbay-labs/clawdstrike).  Each guard
//! implements `arc_kernel::Guard` and can be registered on the kernel via
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
//! use arc_guards::GuardPipeline;
//!
//! let pipeline = GuardPipeline::default_pipeline();
//! kernel.add_guard(Box::new(pipeline));
//! ```

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod action;
mod path_normalization;

pub mod external;

pub mod advisory;
pub mod agent_velocity;
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

pub use advisory::{
    AdvisoryGuard, AdvisoryPipeline, AdvisorySeverity, AdvisorySignal, AnomalyAdvisoryGuard,
    DataTransferAdvisoryGuard, GuardOutput, PromotionPolicy, PromotionRule,
};
pub use agent_velocity::{AgentVelocityConfig, AgentVelocityGuard};
pub use behavioral_sequence::{BehavioralSequenceGuard, SequencePolicy};
pub use data_flow::{DataFlowConfig, DataFlowGuard};
pub use egress_allowlist::EgressAllowlistGuard;
pub use forbidden_path::ForbiddenPathGuard;
pub use internal_network::InternalNetworkGuard;
pub use jailbreak::{
    JailbreakGuard, JailbreakGuardConfig, DEFAULT_FINGERPRINT_CAPACITY as JAILBREAK_DEFAULT_FINGERPRINT_CAPACITY,
};
pub use jailbreak_detector::{
    DetectorConfig as JailbreakDetectorConfig, Detection as JailbreakDetection, JailbreakCategory,
    JailbreakDetector, LayerScores as JailbreakLayerScores, LayerWeights,
    LinearModel as JailbreakLinearModel, Signal as JailbreakSignal,
    StatisticalThresholds as JailbreakStatisticalThresholds,
    DEFAULT_DENY_THRESHOLD as JAILBREAK_DEFAULT_DENY_THRESHOLD,
};
pub use mcp_tool::McpToolGuard;
pub use patch_integrity::PatchIntegrityGuard;
pub use path_allowlist::PathAllowlistGuard;
pub use pipeline::GuardPipeline;
pub use post_invocation::{PostInvocationHook, PostInvocationPipeline, PostInvocationVerdict};
pub use prompt_injection::{
    Detection as PromptInjectionDetection, PromptInjectionConfig, PromptInjectionGuard,
    Signal as PromptInjectionSignal,
};
pub use response_sanitization::{
    ResponseSanitizationGuard, SanitizationAction, ScanResult, SensitivityLevel,
};
pub use secret_leak::SecretLeakGuard;
pub use shell_command::ShellCommandGuard;
pub use velocity::VelocityGuard;

pub use action::{extract_action, ToolAction};

pub use external::{
    AsyncGuardAdapter, AsyncGuardAdapterBuilder, AsyncGuardAdapterConfig, CircuitBreaker,
    CircuitBreakerConfig, CircuitOpenVerdict, CircuitState, ExternalGuard, ExternalGuardError,
    GuardCallContext, RateLimitedVerdict, RetryConfig, TokenBucket, TtlCache,
};
