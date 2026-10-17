//! Response sanitization guard: scans tool results for secrets, PII/PHI,
//! and other sensitive data, then redacts them before the agent sees them.
//!
//! [`OutputSanitizer`] carries the secret, PII and PHI detectors, the
//! configurable allowlist/denylist, deterministic overlap resolution, and the
//! redaction strategies. `SanitizerHook` runs it on the post-invocation path.
//!
//! The sanitizer fails closed: if a built-in pattern fails to compile, the
//! whole scanned output is redacted.

mod detectors;
mod formatting;
mod overlap;
mod sanitizer;
mod types;
mod validators;
mod vault;

pub use sanitizer::OutputSanitizer;
pub use types::{
    AllowlistConfig, CategoryConfig, DenylistConfig, EntropyConfig, OutputSanitizerConfig,
    OutputSanitizerConfigError, ProcessingStats, Redaction, RedactionStrategy, SanitizationResult,
    SanitizedValue, SensitiveCategory, SensitiveDataFinding, Span,
};
pub use vault::TokenVault;

#[cfg(test)]
mod tests;
