use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, SecurityInvocationContextV1};
pub use chio_security_types::ports::ContainmentTargetKind;
use chio_security_types::ports::{
    containment_target as derive_containment_target, ContainmentOverlayStore, PortError,
    TenantScopedId,
};

use crate::MissingContextPolicy;

const GUARD_NAME: &str = "chio-containment-overlay";

pub fn containment_target(
    context: &SecurityInvocationContextV1,
    kind: ContainmentTargetKind,
    authoritative_id: &str,
) -> Result<TenantScopedId, PortError> {
    derive_containment_target(context.tenant_id(), kind, authoritative_id)
}

pub struct ContainmentGuard {
    overlays: Arc<dyn ContainmentOverlayStore>,
    missing_context: MissingContextPolicy,
}

impl ContainmentGuard {
    #[must_use]
    pub fn new(
        overlays: Arc<dyn ContainmentOverlayStore>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            overlays,
            missing_context,
        }
    }

    fn deny(reason: &str) -> GuardDecision {
        GuardDecision::deny(vec![GuardEvidence {
            guard_name: GUARD_NAME.to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        }])
    }

    fn evaluate_target(
        &self,
        context: &SecurityInvocationContextV1,
        kind: ContainmentTargetKind,
        authoritative_id: &str,
    ) -> Result<Option<GuardDecision>, PortError> {
        let target = containment_target(context, kind, authoritative_id)?;
        let Some(snapshot) = self.overlays.load_effective(&target)? else {
            return Ok(None);
        };
        let has_contributions = !snapshot.active_contributions.is_empty();
        if (snapshot.effective_posture_rank == 0) == has_contributions {
            return Err(PortError::integrity_failure());
        }
        if snapshot.effective_posture_rank == 0 {
            return Ok(None);
        }
        Ok(Some(Self::deny(&format!(
            "active {} containment overlay denied the invocation",
            kind.as_str()
        ))))
    }
}

impl Guard for ContainmentGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn evaluate(&self, guard_context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let Some(context) = guard_context
            .security_context()
            .map(|security| security.as_v1())
        else {
            return Ok(if self.missing_context.denies() {
                Self::deny("authoritative security context is missing")
            } else {
                GuardDecision::allow()
            });
        };
        let targets = [
            (
                ContainmentTargetKind::Session,
                context.session_id().as_str(),
            ),
            (
                ContainmentTargetKind::Principal,
                context.principal_id().as_str(),
            ),
            (
                ContainmentTargetKind::Lineage,
                context.lineage_root_id().as_str(),
            ),
            (
                ContainmentTargetKind::Capability,
                guard_context.request.capability.id.as_str(),
            ),
        ];
        for (kind, authoritative_id) in targets {
            match self.evaluate_target(context, kind, authoritative_id) {
                Ok(Some(decision)) => return Ok(decision),
                Ok(None) => {}
                Err(error) => {
                    return Ok(Self::deny(&format!(
                        "{} containment overlay lookup failed: {error}",
                        kind.as_str()
                    )));
                }
            }
        }
        Ok(GuardDecision::allow())
    }
}
