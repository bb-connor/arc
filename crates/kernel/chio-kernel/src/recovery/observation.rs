//! Read-only authentication of an original token. This observation neither
//! admits its grants nor checks or consumes invocation budgets.
use super::{AuthenticatedRecoveryActor, RecoveryPermission};
use chio_security_types::recovery::WorkflowId;

impl crate::ChioKernel {
    pub fn observe_recovery_capability_liveness(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<bool, crate::KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if !matches!(
            actor.permission(),
            RecoveryPermission::Inspect | RecoveryPermission::InspectExplanationGraph
        ) {
            return Err(crate::KernelError::DurableAdmission(
                "recovery observation refused".into(),
            ));
        }
        let record = self.read_recovery_workflow(actor, workflow)?;
        Ok(self
            .validate_non_tool_capability(
                &record.seed.capability,
                &record.seed.capability.subject.to_hex(),
            )
            .is_ok())
    }
}
