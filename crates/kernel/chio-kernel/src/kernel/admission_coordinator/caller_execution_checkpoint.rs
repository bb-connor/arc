//! Test-only observation of caller ownership and dispatch commitment.

use super::{AdmissionOperationV1, ChioKernel};
use crate::admission_operation::AdmissionCallerBudgetShare;
use std::sync::Arc;

/// A caller lifecycle boundary that a harness can deterministically interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerExecutionCheckpoint {
    /// The caller owns a funded hold, before acquiring the sibling registry lock.
    BeforeShareAdmission,
    /// Dispatch and invocation capture are durable, with post-dispatch cleanup
    /// ownership armed, but the caller report has not been recorded as a return.
    DispatchCommitted,
}

/// No observer storage or call site exists without admission test support.
pub type CallerExecutionCheckpointHook =
    Arc<dyn Fn(CallerExecutionCheckpoint, &AdmissionOperationV1) + Send + Sync>;

impl ChioKernel {
    /// Install a deterministic caller lifecycle observer for a harness.
    pub fn install_caller_execution_checkpoint_hook(
        &mut self,
        hook: CallerExecutionCheckpointHook,
    ) {
        self.caller_execution_checkpoint_hook = Some(hook);
    }

    pub(crate) fn reach_caller_execution_checkpoint(
        &self,
        checkpoint: CallerExecutionCheckpoint,
        operation: &AdmissionOperationV1,
    ) {
        if !AdmissionCallerBudgetShare::is_owned_by(operation) {
            return;
        }
        if let Some(hook) = self.caller_execution_checkpoint_hook.as_ref() {
            hook(checkpoint, operation);
        }
    }
}
