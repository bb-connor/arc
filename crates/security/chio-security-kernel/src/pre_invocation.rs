use std::sync::Arc;

use crate::MissingContextPolicy;
use chio_core::receipt::metadata::GuardEvidence;
use chio_flow::{evaluate_pre_invocation, FlowAdmission, FlowDenial, ResolvedFlowRequest};
use chio_kernel::{
    Guard, GuardContext, GuardDecision, KernelError, SecurityInvocationContextV1, ToolCallRequest,
};

pub struct FlowPreInvocationInput<'a> {
    pub security_context: &'a SecurityInvocationContextV1,
    pub request: &'a ToolCallRequest,
}

pub trait FlowPreInvocationResolver: Send + Sync {
    fn resolve(
        &self,
        input: &FlowPreInvocationInput<'_>,
    ) -> Result<ResolvedFlowRequest, FlowDenial>;

    fn persist(&self, admission: &FlowAdmission) -> Result<(), FlowDenial>;
}

pub trait FlowPreInvocationPort: Send + Sync {
    fn evaluate(&self, input: &FlowPreInvocationInput<'_>) -> Result<(), FlowDenial>;
}

/// Pre-invocation flow adapter for requests that do not declassify data.
///
/// A verified declassification remains fail-closed here because this adapter
/// has no one-shot consumption authority. Production declassification must use
/// the paired pre-dispatch path that consumes and evidences the grant before
/// connector entry.
pub struct EngineFlowPreInvocationPort {
    resolver: Arc<dyn FlowPreInvocationResolver>,
}

impl EngineFlowPreInvocationPort {
    #[must_use]
    pub fn new(resolver: Arc<dyn FlowPreInvocationResolver>) -> Self {
        Self { resolver }
    }
}

impl FlowPreInvocationPort for EngineFlowPreInvocationPort {
    fn evaluate(&self, input: &FlowPreInvocationInput<'_>) -> Result<(), FlowDenial> {
        let resolved = self.resolver.resolve(input)?;
        let admission = evaluate_pre_invocation(resolved)?;
        self.resolver.persist(&admission)
    }
}

pub struct FlowPreInvocationGuard {
    flow: Arc<dyn FlowPreInvocationPort>,
    missing_context: MissingContextPolicy,
}

impl FlowPreInvocationGuard {
    #[must_use]
    pub fn new(
        flow: Arc<dyn FlowPreInvocationPort>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            flow,
            missing_context,
        }
    }

    fn deny(reason: &str) -> GuardDecision {
        GuardDecision::deny(vec![GuardEvidence {
            guard_name: "chio-flow-pre-invocation".to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        }])
    }
}

impl Guard for FlowPreInvocationGuard {
    fn name(&self) -> &str {
        "chio-flow-pre-invocation"
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let Some(security_context) = context.security_context().map(|value| value.as_v1()) else {
            return Ok(if self.missing_context.denies() {
                Self::deny("authoritative security context is missing")
            } else {
                GuardDecision::allow()
            });
        };
        let input = FlowPreInvocationInput {
            security_context,
            request: context.request,
        };
        Ok(match self.flow.evaluate(&input) {
            Ok(()) => GuardDecision::allow(),
            Err(error) => Self::deny(&format!("flow denied: {error}")),
        })
    }
}
