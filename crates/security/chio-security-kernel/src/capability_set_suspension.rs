use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};
use chio_security_types::ports::{
    validate_capability_suspension_decision, CapabilitySetSuspensionStore,
    CapabilitySuspensionQuery, RecordId,
};

use crate::MissingContextPolicy;

const GUARD_NAME: &str = "chio-capability-set-suspension";

/// Fail-closed pre-dispatch guard for exact capability-set deny contributions.
pub struct CapabilitySetSuspensionGuard {
    suspensions: Arc<dyn CapabilitySetSuspensionStore>,
    missing_context: MissingContextPolicy,
}

impl CapabilitySetSuspensionGuard {
    #[must_use]
    pub fn new(
        suspensions: Arc<dyn CapabilitySetSuspensionStore>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            suspensions,
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
}

impl Guard for CapabilitySetSuspensionGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let Some(security) = context.security_context().map(|value| value.as_v1()) else {
            return Ok(if self.missing_context.denies() {
                Self::deny("authoritative tenant context is missing")
            } else {
                GuardDecision::allow()
            });
        };
        let capability_id = match RecordId::new(context.request.capability.id.as_str()) {
            Ok(value) => value,
            Err(_) => return Ok(Self::deny("capability identity is invalid")),
        };
        let query = CapabilitySuspensionQuery {
            tenant_id: security.tenant_id().clone(),
            capability_id,
        };
        let decision = match self.suspensions.evaluate_capability_suspension(&query) {
            Ok(value) => value,
            Err(_) => return Ok(Self::deny("capability suspension lookup failed")),
        };
        if validate_capability_suspension_decision(&query, &decision).is_err() {
            return Ok(Self::deny("capability suspension result failed validation"));
        }
        if decision.denied {
            return Ok(Self::deny("capability is in an active suspended set"));
        }
        Ok(GuardDecision::allow())
    }
}
