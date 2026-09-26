//! Why a response dispatch was refused.
//!
//! One variant per rule, so a test, a receipt and an operator can each tell
//! which rule fired. A variant names the rule and carries the values the rule
//! compared; it never carries bytes the requester supplied.

use crate::ports::ResponseDispatchCommitMode;
use crate::response_execution::{ResponseExecutionBindingError, ResponseExecutionMode};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchRejection {
    /// The plan predates execution bindings. Its historical evidence stays
    /// decodable; it cannot enter live execution as new work.
    LegacyPlanFreshDispatch,
    /// The plan is bound to a mode other than live execution.
    ExecutionMode { observed: ResponseExecutionMode },
    /// The plan carries a binding this reader does not understand.
    ExecutionBinding(ResponseExecutionBindingError),
    /// The authorization was issued for a different operator capability.
    CapabilityDigestMismatch,
    /// Generation zero is the unassigned executor authority.
    ZeroExecutorGeneration,
    /// The authorization time lies outside `[created_at, expires_at)`.
    AuthorizationOutsideWindow {
        authorized_at_unix_ms: u64,
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    },
    /// The first lease must end after the authorization and no later than
    /// the plan: `(authorized_at, expires_at]`.
    LeaseOutsideWindow {
        lease_expires_at_unix_ms: u64,
        authorized_at_unix_ms: u64,
        plan_expires_at_unix_ms: u64,
    },
    /// The approval is of a different kind than the plan requires.
    ApprovalRequirementMismatch,
    /// A governed approval names admission operation version zero.
    ZeroAdmissionOperationVersion,
    /// A committed resume replays a governed admission; an automatic plan has
    /// none to replay.
    ResumeRequiresGovernedApproval {
        commit_mode: ResponseDispatchCommitMode,
    },
    /// A dispatch snapshot records the executor binding it was prepared under.
    SnapshotWithoutExecutionDispatch,
    /// The authorization hash is attached exactly once, by the dispatch commit.
    SnapshotAlreadyAuthorized,
}

impl fmt::Display for DispatchRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyPlanFreshDispatch => formatter.write_str(
                "response plan carries no execution binding and cannot enter live execution",
            ),
            Self::ExecutionMode { observed } => write!(
                formatter,
                "response plan is bound to {} execution; live execution requires {}",
                observed.as_str(),
                ResponseExecutionMode::Live.as_str()
            ),
            Self::ExecutionBinding(error) => {
                write!(formatter, "response plan execution binding is invalid: {error}")
            }
            Self::CapabilityDigestMismatch => formatter.write_str(
                "authorization capability digest does not match the plan operator capability",
            ),
            Self::ZeroExecutorGeneration => {
                formatter.write_str("executor authority generation zero cannot authorize a dispatch")
            }
            Self::AuthorizationOutsideWindow {
                authorized_at_unix_ms,
                created_at_unix_ms,
                expires_at_unix_ms,
            } => write!(
                formatter,
                "dispatch authorized at {authorized_at_unix_ms}, outside the plan window [{created_at_unix_ms}, {expires_at_unix_ms})"
            ),
            Self::LeaseOutsideWindow {
                lease_expires_at_unix_ms,
                authorized_at_unix_ms,
                plan_expires_at_unix_ms,
            } => write!(
                formatter,
                "initial lease ends at {lease_expires_at_unix_ms}, outside ({authorized_at_unix_ms}, {plan_expires_at_unix_ms}]"
            ),
            Self::ApprovalRequirementMismatch => formatter.write_str(
                "dispatch approval kind does not match the plan approval requirement",
            ),
            Self::ZeroAdmissionOperationVersion => {
                formatter.write_str("governed approval names admission operation version zero")
            }
            Self::ResumeRequiresGovernedApproval { commit_mode } => write!(
                formatter,
                "commit mode {commit_mode:?} replays a governed admission; the plan has none"
            ),
            Self::SnapshotWithoutExecutionDispatch => {
                formatter.write_str("response snapshot carries no execution dispatch binding")
            }
            Self::SnapshotAlreadyAuthorized => formatter
                .write_str("response snapshot already carries a dispatch authorization hash"),
        }
    }
}

impl core::error::Error for DispatchRejection {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ExecutionBinding(error) => Some(error),
            Self::LegacyPlanFreshDispatch
            | Self::ExecutionMode { .. }
            | Self::CapabilityDigestMismatch
            | Self::ZeroExecutorGeneration
            | Self::AuthorizationOutsideWindow { .. }
            | Self::LeaseOutsideWindow { .. }
            | Self::ApprovalRequirementMismatch
            | Self::ZeroAdmissionOperationVersion
            | Self::ResumeRequiresGovernedApproval { .. }
            | Self::SnapshotWithoutExecutionDispatch
            | Self::SnapshotAlreadyAuthorized => None,
        }
    }
}

impl From<ResponseExecutionBindingError> for DispatchRejection {
    fn from(error: ResponseExecutionBindingError) -> Self {
        Self::ExecutionBinding(error)
    }
}
