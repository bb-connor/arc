//! Recovery authority is minted only by the parent durable verifier. A public
//! commit mode or a deserialized plan cannot construct either token.

use super::{ActiveResponseDispatchPermit, ActiveResponseExecutionRequestParts};

pub(in crate::kernel) enum RecoveredDispatchApproval {
    Automatic,
    Governed(Box<ActiveResponseDispatchPermit>),
}

pub(in crate::kernel) struct CommittedDispatchAuthority {
    execution: ActiveResponseExecutionRequestParts,
    approval: RecoveredDispatchApproval,
}

impl CommittedDispatchAuthority {
    pub(super) fn new(
        execution: ActiveResponseExecutionRequestParts,
        approval: RecoveredDispatchApproval,
    ) -> Self {
        Self {
            execution,
            approval,
        }
    }

    pub(in crate::kernel) fn execution(&self) -> &ActiveResponseExecutionRequestParts {
        &self.execution
    }

    pub(super) fn approval(&self) -> &RecoveredDispatchApproval {
        &self.approval
    }
}

/// A governed admission commitment whose executor dispatch does not yet exist.
/// It permits only resuming that exact admission, never claiming a dispatch row.
pub(in crate::kernel) struct CommittedAdmissionAuthority {
    execution: ActiveResponseExecutionRequestParts,
    permit: ActiveResponseDispatchPermit,
}

impl CommittedAdmissionAuthority {
    pub(super) fn new(
        execution: ActiveResponseExecutionRequestParts,
        permit: ActiveResponseDispatchPermit,
    ) -> Self {
        Self { execution, permit }
    }

    pub(in crate::kernel) fn execution(&self) -> &ActiveResponseExecutionRequestParts {
        &self.execution
    }

    pub(super) fn permit(&self) -> &ActiveResponseDispatchPermit {
        &self.permit
    }
}
