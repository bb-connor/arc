//! `ChioKernel` tool-call and plan evaluation path.
//!
//! Holds the synchronous and asynchronous evaluate entrypoints, the plan
//! evaluation helpers, and the long-form evaluation cores.

use chio_log_redact::redacted;

use self::responses::FinalizeToolOutputCostContext;
use super::*;

mod async_evaluation_core;
mod async_nonce_preflight;
mod caller_execution;
mod delivery_preparation;
mod evaluation_entry;
pub(crate) mod evaluation_helpers;
mod invocation_capture;
mod nested_flow_evaluation;
mod nested_flow_grant_selection;
mod sync_evaluation_wrapper;

pub use caller_execution::CallerExecutionReport;

/// Disposition of the pre-execution budget hold when a strict-nonce preflight
/// is reached (nonce required, no nonce presented on the request).
///
/// The preflight is the point in the evaluation pipeline where the capability,
/// DPoP, governed-transaction, guard, runtime-admission, and budget checks have
/// all passed but the tool has not yet been dispatched. What happens to the
/// reserved hold there depends on who executes the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreflightHoldDisposition {
    /// Reverse the pre-execution hold and return an incomplete preflight
    /// receipt. The same kernel re-takes the hold when the caller retries
    /// presenting the minted nonce, then dispatches the tool. This is the
    /// default for every in-process strict-nonce dispatch surface.
    ReverseForRetry,
    /// Keep the pre-execution hold reserved (open) and return a
    /// non-authoritative authorization receipt carrying the minted nonce. The
    /// kernel does not dispatch the tool: the caller presents the nonce to the
    /// real tool server, which verifies and consumes it and reconciles the
    /// reserved hold. Used by the sidecar mediated `/v1/evaluate` pre-execution
    /// authorization gate, where the reserved hold enforces `max_total_cost`
    /// against concurrent authorizations. An orphaned reserved hold (the caller
    /// never executes) is fail-closed: budget stays over-reserved until the
    /// crash reaper reclaims it, never over-subscribed.
    ReserveForCaller,
}

/// How an admitted execution request proceeds past its last admission step.
#[derive(Clone)]
pub(crate) enum DispatchMode {
    /// Dispatch to the registered tool server and finalize its return.
    Kernel,
    /// Reserve the executable hold and the nonce, then stop. The caller
    /// executes the tool elsewhere and returns through a reconcile that resumes
    /// the same operation.
    ReserveForCaller,
    /// Resume a caller-reserved operation with the caller's report standing in
    /// for the tool server.
    CallerReport(std::sync::Arc<dyn crate::ToolServerConnection>),
}

/// What an evaluation does at its two decision points: the strict-nonce
/// preflight and the dispatch of an admitted execution request.
#[derive(Clone)]
pub(crate) struct EvaluationDisposition {
    pub(crate) preflight_hold: PreflightHoldDisposition,
    pub(crate) dispatch: DispatchMode,
}

impl EvaluationDisposition {
    /// The in-process default: reverse the preflight hold for a retry and
    /// dispatch to the registered tool server.
    pub(crate) fn kernel() -> Self {
        Self {
            preflight_hold: PreflightHoldDisposition::ReverseForRetry,
            dispatch: DispatchMode::Kernel,
        }
    }

    /// The legacy sidecar reservation: keep the preflight hold open and mint
    /// a nonce for a tool server the kernel never dispatches to.
    pub(crate) fn legacy_reservation() -> Self {
        Self {
            preflight_hold: PreflightHoldDisposition::ReserveForCaller,
            dispatch: DispatchMode::Kernel,
        }
    }

    /// A durable caller reservation: the ordinary strict preflight, then the
    /// execution's first half stopping once the nonce is reserved.
    pub(crate) fn caller_reservation() -> Self {
        Self {
            preflight_hold: PreflightHoldDisposition::ReverseForRetry,
            dispatch: DispatchMode::ReserveForCaller,
        }
    }

    /// Resume a caller reservation with the caller's report as the server.
    pub(crate) fn caller_report(report: std::sync::Arc<dyn crate::ToolServerConnection>) -> Self {
        Self {
            preflight_hold: PreflightHoldDisposition::ReverseForRetry,
            dispatch: DispatchMode::CallerReport(report),
        }
    }
}

impl DispatchMode {
    pub(crate) fn caller_executed(&self) -> bool {
        !matches!(self, Self::Kernel)
    }

    pub(crate) fn transport(&self) -> crate::kernel::admission_coordinator::DispatchTransport {
        if self.caller_executed() {
            crate::kernel::admission_coordinator::DispatchTransport::CallerReport
        } else {
            crate::kernel::admission_coordinator::DispatchTransport::KernelToolServer
        }
    }
}
