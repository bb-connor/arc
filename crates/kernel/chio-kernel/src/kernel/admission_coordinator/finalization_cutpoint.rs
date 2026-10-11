//! Process-kill points inside durable finalization.
//!
//! Commit points leave state the next process must finish from: the recorded return,
//! the begun or resolved evaluation, or the terminal projection whose receipt
//! log append never happened. Production builds carry no hook storage; the
//! test-support feature lets a harness observe each point and kill the process.
//! The release-acknowledged point deliberately precedes its checkpoint, testing
//! that a lost live owner cannot be replaced by a fresh successful callback.

#[cfg(feature = "admission-test-support")]
use std::sync::Arc;

use super::ChioKernel;

/// A commit or explicit acknowledgement boundary inside tool finalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DurableFinalizationCutpoint {
    /// The raw return and its outcome record are durable and the operation is
    /// `Finalizing` without an evaluation.
    ToolReturnRecorded,
    /// The post-return evaluation record is durable in its evaluating state.
    PostReturnEvaluationBegun,
    /// The evaluation and the tool outcome are resolved; the operation is still
    /// `Finalizing`.
    PostReturnResolved,
    /// The live owner acknowledged release but no checkpoint has committed.
    SecurityReleaseAcknowledged,
    /// Final release is durably bound to this exact outcome and evaluation.
    SecurityReleaseCheckpointed,
    /// The terminal projection is durable; the receipt log append, mirrors and
    /// the response have not happened.
    TerminalProjected,
}

impl DurableFinalizationCutpoint {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "tool-return-recorded" => Some(Self::ToolReturnRecorded),
            "post-return-evaluation-begun" => Some(Self::PostReturnEvaluationBegun),
            "post-return-resolved" => Some(Self::PostReturnResolved),
            "security-release-acknowledged" => Some(Self::SecurityReleaseAcknowledged),
            "security-release-checkpointed" => Some(Self::SecurityReleaseCheckpointed),
            "terminal-projected" => Some(Self::TerminalProjected),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ToolReturnRecorded => "tool-return-recorded",
            Self::PostReturnEvaluationBegun => "post-return-evaluation-begun",
            Self::PostReturnResolved => "post-return-resolved",
            Self::SecurityReleaseAcknowledged => "security-release-acknowledged",
            Self::SecurityReleaseCheckpointed => "security-release-checkpointed",
            Self::TerminalProjected => "terminal-projected",
        }
    }
}

/// Observer a harness installs to act at a cutpoint, typically by killing
/// the process.
#[cfg(feature = "admission-test-support")]
pub type DurableFinalizationCutpointHook = Arc<dyn Fn(DurableFinalizationCutpoint) + Send + Sync>;

impl ChioKernel {
    /// Install the observer that finalization reaches at every cutpoint.
    #[cfg(feature = "admission-test-support")]
    pub fn install_durable_finalization_cutpoint(&mut self, hook: DurableFinalizationCutpointHook) {
        self.durable_finalization_cutpoint_hook = Some(hook);
    }

    #[cfg(feature = "admission-test-support")]
    pub(crate) fn reach_durable_finalization_cutpoint(
        &self,
        cutpoint: DurableFinalizationCutpoint,
    ) {
        if let Some(hook) = self.durable_finalization_cutpoint_hook.as_ref() {
            hook(cutpoint);
        }
    }

    #[cfg(not(feature = "admission-test-support"))]
    pub(crate) fn reach_durable_finalization_cutpoint(
        &self,
        cutpoint: DurableFinalizationCutpoint,
    ) {
        let _ = cutpoint;
    }
}
