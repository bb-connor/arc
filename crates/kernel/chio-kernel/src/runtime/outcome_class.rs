use chio_core::session::OperationTerminalState;

use crate::admission_operation::{AdmissionOperationState, AdmissionReceiptMetadataV1};

use super::{ToolCallResponse, Verdict};

/// What a tool-call response means for the operation it answers.
///
/// Only `OutcomeUnknownAfterDispatch` describes an operation whose effect may
/// have happened; every other class is final for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallOutcomeClass {
    /// The call was admitted.
    Allowed,
    /// The call is suspended pending a human decision.
    PendingApproval,
    /// The call was refused by policy or validation.
    Denied,
    /// The kernel dispatched the call and retained no recorded outcome, so the
    /// refusal describes uncertainty rather than a policy decision.
    OutcomeUnknownAfterDispatch,
    /// The request ended in a cancelled terminal state.
    Cancelled,
    /// The request ended in an incomplete terminal state.
    Incomplete,
}

impl ToolCallResponse {
    /// Classify this response from its verdict, terminal state and the typed
    /// admission projection on its receipt.
    ///
    /// Receipts whose admission metadata is absent, thin, or unrecognized never
    /// classify as `OutcomeUnknownAfterDispatch`: they remain signed evidence
    /// but cannot authorize a fresh dispatch.
    pub fn outcome_class(&self) -> ToolCallOutcomeClass {
        if self.verdict == Verdict::Deny && self.retains_unknown_outcome() {
            return ToolCallOutcomeClass::OutcomeUnknownAfterDispatch;
        }
        match (&self.terminal_state, self.verdict) {
            (OperationTerminalState::Cancelled { .. }, _) => ToolCallOutcomeClass::Cancelled,
            (OperationTerminalState::Incomplete { .. }, _) => ToolCallOutcomeClass::Incomplete,
            (OperationTerminalState::Completed, Verdict::Allow) => ToolCallOutcomeClass::Allowed,
            (OperationTerminalState::Completed, Verdict::Deny) => ToolCallOutcomeClass::Denied,
            (OperationTerminalState::Completed, Verdict::PendingApproval) => {
                ToolCallOutcomeClass::PendingApproval
            }
        }
    }

    fn retains_unknown_outcome(&self) -> bool {
        let Some(metadata) = self
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("admission_operation"))
        else {
            return false;
        };
        let Ok(projection) = serde_json::from_value::<AdmissionReceiptMetadataV1>(metadata.clone())
        else {
            return false;
        };
        projection.projected_state == AdmissionOperationState::OutcomeUnknownAfterDispatch
            && projection.request_id.as_str() == self.request_id
            && projection.retained_dispatch_commit.is_some()
            && projection.tool_outcome_id.is_none()
            && projection.tool_outcome_version.is_none()
    }
}
