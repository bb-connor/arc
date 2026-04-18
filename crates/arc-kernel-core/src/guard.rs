//! Sync guard trait for portable evaluation.
//!
//! This matches the legacy `arc_kernel::Guard` surface byte-for-byte so
//! existing guard implementations can be lifted into the core with no
//! behavioural change:
//!
//! ```ignore
//! pub trait Guard: Send + Sync {
//!     fn name(&self) -> &str;
//!     fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelCoreError>;
//! }
//! ```
//!
//! The error type is [`crate::evaluate::KernelCoreError`] instead of the
//! legacy `arc_kernel::KernelError` because the full error enum carries
//! std/tokio/sqlite-flavoured variants that are not portable. The legacy
//! adapter in `arc-kernel::kernel` bridges the two.

use alloc::string::String;

use arc_core_types::capability::ArcScope;

use crate::Verdict;

/// Sync guard trait. Preserved signature-for-signature from legacy
/// `arc_kernel::Guard`.
pub trait Guard: Send + Sync {
    /// Human-readable guard name (e.g. `forbidden-path`).
    fn name(&self) -> &str;

    /// Evaluate this guard against a tool-call context.
    ///
    /// Returns `Ok(Verdict::Allow)` to pass, `Ok(Verdict::Deny)` to block,
    /// or `Err(KernelCoreError)` to signal an internal guard failure (which
    /// the kernel core treats as a fail-closed deny).
    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<Verdict, crate::KernelCoreError>;
}

/// Inputs a guard sees when it runs inside the core evaluate pipeline.
///
/// Mirrors `arc_kernel::GuardContext` with two deliberate restrictions:
///
/// - `request` carries only the portable shape (no `dpop_proof`,
///   `governed_intent`, `approval_token`, or `model_metadata` -- those are
///   full-kernel concerns). The legacy adapter in `arc-kernel` builds a
///   temporary [`PortableToolCallRequest`] when it runs the core evaluate
///   pipeline.
/// - `session_filesystem_roots` stays in the portable surface so the
///   filesystem-roots guard (today the only session-aware guard) can run
///   unchanged on every platform.
pub struct GuardContext<'a> {
    /// The tool call request being evaluated.
    pub request: &'a PortableToolCallRequest,
    /// The verified capability scope.
    pub scope: &'a ArcScope,
    /// The agent making the request.
    pub agent_id: &'a str,
    /// The target server.
    pub server_id: &'a str,
    /// Session-scoped enforceable filesystem roots, when the request is being
    /// evaluated through the supported session-backed runtime path.
    pub session_filesystem_roots: Option<&'a [String]>,
    /// Index of the matched grant in the capability's scope, populated by
    /// [`crate::evaluate`] before guards run.
    pub matched_grant_index: Option<usize>,
}

/// Portable projection of an `arc_kernel::runtime::ToolCallRequest`.
///
/// Contains only the fields the sync core evaluate pipeline needs. Guards
/// that want DPoP/governed/approval inputs must stay in `arc-kernel`.
#[derive(Debug, Clone)]
pub struct PortableToolCallRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// The tool to invoke.
    pub tool_name: String,
    /// The server hosting the tool.
    pub server_id: String,
    /// The calling agent's identifier (hex-encoded public key).
    pub agent_id: String,
    /// Tool arguments as canonical JSON.
    pub arguments: serde_json::Value,
}
