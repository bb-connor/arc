use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};
use chio_security_types::ports::{
    DestinationId, EgressDestinationQuery, EgressRestrictionDecision, EgressRestrictionSessionKey,
    EgressRestrictionStore,
};

use crate::MissingContextPolicy;

const GUARD_NAME: &str = "chio-egress-restriction";

pub struct EgressRestrictionGuard {
    restrictions: Arc<dyn EgressRestrictionStore>,
    missing_context: MissingContextPolicy,
}

impl EgressRestrictionGuard {
    #[must_use]
    pub fn new(
        restrictions: Arc<dyn EgressRestrictionStore>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            restrictions,
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

    fn validate_decision(
        query: &EgressDestinationQuery,
        decision: &EgressRestrictionDecision,
    ) -> bool {
        decision.key == query.key
            && decision.destination_id == query.destination_id
            && decision.denied != decision.active_effect_ids.is_empty()
    }
}

impl Guard for EgressRestrictionGuard {
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
        let destination_id = match DestinationId::new(guard_context.request.server_id.clone()) {
            Ok(destination_id) => destination_id,
            Err(_) => return Ok(Self::deny("request destination is not canonical")),
        };
        let query = EgressDestinationQuery {
            key: EgressRestrictionSessionKey {
                tenant_id: context.tenant_id().clone(),
                session_id: context.session_id().clone(),
            },
            destination_id,
        };
        let decision = match self.restrictions.evaluate_destination(&query) {
            Ok(decision) => decision,
            Err(_) => return Ok(Self::deny("egress restriction lookup failed")),
        };
        if !Self::validate_decision(&query, &decision) {
            return Ok(Self::deny("egress restriction result failed validation"));
        }
        if decision.denied {
            return Ok(Self::deny(
                "active destination restriction denied the invocation",
            ));
        }
        Ok(GuardDecision::allow())
    }
}
