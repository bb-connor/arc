//! Tool-call evaluation surface (M05 P1.T1 mechanical extraction).
//!
//! This module is the M05 async-kernel pivot's first incision: it defines a
//! [`ToolEvaluator`] trait that names the four logical phases of a tool-call
//! evaluation (capability validation, guard pipeline, dispatch, receipt
//! signing) so subsequent M05 tickets can replace each phase with a truly
//! async implementation without re-shaping the public surface again.
//!
//! T1 is deliberately MECHANICAL. The default implementation delegates to the
//! existing synchronous helpers on [`crate::ChioKernel`] via
//! `tokio::task::block_in_place` (when running inside a multi-threaded tokio
//! runtime) or a direct call (otherwise). No behaviour change is intended.
//! The byte-identity regression test in M05.P1.T7 will assert this stays true
//! across the dual-track release window.
//!
//! ## Migration sequence
//!
//! - **T1 (merged)**: trait shape only, default body wraps the existing
//!   sync entrypoint. Public `ChioKernel::evaluate_tool_call` continues to
//!   route through the crate-internal sync helper exactly as it did before;
//!   the only structural change is that the routing now passes through
//!   `BlockingToolEvaluator::default().evaluate(&kernel, request)`.
//! - **T2 (this commit)**: rename the long-form sync entrypoint from
//!   `evaluate_tool_call_sync_with_session_roots` to
//!   `evaluate_tool_call_sync_inner` and mark it `#[doc(hidden)]`. The public
//!   surface remains the trait method (and the `evaluate_tool_call_sync`
//!   crate-private shim added in T1).
//! - **T3**: replace [`ToolEvaluator::sign_receipt`]'s default body with an
//!   mpsc-backed signing task; receipt signing leaves the lock-step path.
//! - **T4**: replace [`ToolEvaluator::dispatch`]'s default body with a real
//!   async dispatch.
//! - **T5-T7**: deprecate `evaluate_tool_call_blocking`, gate behind
//!   `legacy-sync` feature flag, byte-identity regression test.
//!
//! See `.planning/trajectory/05-async-kernel-real.md` Phase 1 for the full
//! sequence and `.planning/audits/M05-async-kernel.md` for the audit trail.

use crate::kernel::ChioKernel;
use crate::{KernelError, ToolCallRequest, ToolCallResponse, Verdict};

/// The four logical phases of a tool-call evaluation, surfaced as an
/// async-capable trait so subsequent M05 tickets can swap each phase out for
/// a truly async implementation without re-shaping the public surface again.
///
/// ## T1 contract
///
/// Implementations are required to preserve the semantics of
/// `ChioKernel::evaluate_tool_call_sync_inner` (the doc(hidden) crate-internal
/// sync helper, renamed from `evaluate_tool_call_sync_with_session_roots` in
/// T2). The default [`BlockingToolEvaluator`] satisfies this trivially by
/// delegating to that helper via the `evaluate_tool_call_sync` shim. Custom
/// implementations that diverge from those semantics belong in later tickets
/// (T3+) under explicit feature flags.
///
/// ## Step methods
///
/// The four step methods (`validate_capability`, `run_guards`, `dispatch`,
/// `sign_receipt`) are placeholders for the post-T1 async migration: their
/// default bodies forward to [`Self::evaluate`] by routing through the full
/// synchronous pipeline so callers cannot accidentally drift onto a partial
/// path. They are marked `async` so future tickets can replace the body
/// without touching the trait shape.
#[allow(async_fn_in_trait)]
pub trait ToolEvaluator: Send + Sync {
    /// Run the full evaluation pipeline for `request` against `kernel` and
    /// return the resulting `ToolCallResponse`.
    ///
    /// This is the sole entry point called from `ChioKernel::evaluate_tool_call`
    /// in T1; the per-step methods below exist purely as forward-looking hooks.
    async fn evaluate(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError>;

    /// Validate the capability token attached to `request`.
    ///
    /// In T1 the default body routes through [`Self::evaluate`] and returns
    /// the verdict implied by the resulting response. T3+ will replace this
    /// with a direct async-native validation step.
    async fn validate_capability(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<Verdict, KernelError> {
        let response = self.evaluate(kernel, request).await?;
        Ok(response.verdict)
    }

    /// Run the registered guard pipeline against `request`.
    ///
    /// In T1 the default body routes through [`Self::evaluate`] for the same
    /// reason as [`Self::validate_capability`].
    async fn run_guards(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<Verdict, KernelError> {
        let response = self.evaluate(kernel, request).await?;
        Ok(response.verdict)
    }

    /// Dispatch the validated request to the appropriate tool server.
    ///
    /// In T1 the default body routes through [`Self::evaluate`]. T4 will
    /// replace this with a direct async dispatch path.
    async fn dispatch(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate(kernel, request).await
    }

    /// Sign the receipt for the (allow or deny) outcome of `request`.
    ///
    /// In T1 the default body routes through [`Self::evaluate`]. T3 will
    /// replace this with the mpsc-backed signing task so producers `.await`
    /// on a channel rather than on a mutex.
    async fn sign_receipt(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate(kernel, request).await
    }
}

/// Default [`ToolEvaluator`] implementation: delegates the entire pipeline
/// to the existing synchronous flow on [`ChioKernel`].
///
/// Inside a multi-threaded tokio runtime the call is wrapped in
/// `tokio::task::block_in_place` so the worker thread is released back to
/// the scheduler while the synchronous body runs. Outside such a runtime
/// (current-thread runtime, or no runtime at all) the call is direct: the
/// existing public sync entrypoint already handles those cases.
///
/// This struct deliberately carries no state. T3 will introduce a stateful
/// variant (e.g. `MpscSignedToolEvaluator`) that holds the signing channel.
#[derive(Debug, Default, Clone, Copy)]
pub struct BlockingToolEvaluator;

impl ToolEvaluator for BlockingToolEvaluator {
    async fn evaluate(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        // Reach into the existing synchronous pipeline. The wrapper isolates
        // the (potentially blocking) sync work from the async runtime when
        // we are inside one; otherwise it is a direct call.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| kernel.evaluate_tool_call_sync(request))
            }
            _ => kernel.evaluate_tool_call_sync(request),
        }
    }
}
