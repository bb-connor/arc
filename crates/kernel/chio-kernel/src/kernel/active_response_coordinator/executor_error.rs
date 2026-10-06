//! Preserve executor refusal and availability categories at the kernel boundary.

use super::super::ActiveResponseExecutorError;
use super::{active_response_denied, active_response_internal, KernelError};

pub(super) fn map_executor_dispatch_error(error: ActiveResponseExecutorError) -> KernelError {
    match error {
        ActiveResponseExecutorError::DispatchRejectedBeforeCommit(rejection) => {
            KernelError::ResponseDispatchRejected(rejection)
        }
        ActiveResponseExecutorError::RejectedBeforeCommit(reason) => active_response_denied(
            format!("active-response executor rejected dispatch before commit: {reason}"),
        ),
        ActiveResponseExecutorError::NotReady(reason) => active_response_internal(format!(
            "active-response executor became unavailable: {reason}"
        )),
        ActiveResponseExecutorError::OutcomeUnknown(reason) => active_response_internal(format!(
            "active-response executor outcome requires retry: {reason}"
        )),
    }
}
