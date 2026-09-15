use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
use chio_flow::{evaluate_post_invocation, FlowDenial, PostInvocationFlow};
use chio_kernel::{
    PostInvocationContext, PostInvocationHook, PostInvocationInspection, PostInvocationVerdict,
    SecurityInvocationContextV1, ToolCallRequest,
};
use chio_security_types::ports::FlowJoinRequest;
use chio_security_types::ports::TripwireDetectorPort;
use serde_json::Value;

use crate::tripwire::{RawOutputTripwireEvaluator, TripwireEventPublisher};
use crate::MissingContextPolicy;

pub struct FlowPostInvocationInput<'a> {
    pub security_context: &'a SecurityInvocationContextV1,
    pub request: &'a ToolCallRequest,
    pub response: &'a Value,
}

pub trait FlowPostInvocationResolver: Send + Sync {
    fn resolve(
        &self,
        input: &FlowPostInvocationInput<'_>,
    ) -> Result<PostInvocationFlow, FlowDenial>;

    fn persist(&self, transition: &FlowJoinRequest) -> Result<(), FlowDenial>;
}

pub trait FlowPostInvocationPort: Send + Sync {
    fn evaluate(&self, input: &FlowPostInvocationInput<'_>) -> Result<(), FlowDenial>;
}

pub struct EngineFlowPostInvocationPort {
    resolver: Arc<dyn FlowPostInvocationResolver>,
}

impl EngineFlowPostInvocationPort {
    #[must_use]
    pub fn new(resolver: Arc<dyn FlowPostInvocationResolver>) -> Self {
        Self { resolver }
    }
}

impl FlowPostInvocationPort for EngineFlowPostInvocationPort {
    fn evaluate(&self, input: &FlowPostInvocationInput<'_>) -> Result<(), FlowDenial> {
        let resolved = self.resolver.resolve(input)?;
        let transition = evaluate_post_invocation(resolved)?;
        self.resolver.persist(&transition)
    }
}

pub struct FlowPostInvocationHook {
    flow: Arc<dyn FlowPostInvocationPort>,
    missing_context: MissingContextPolicy,
}

impl FlowPostInvocationHook {
    #[must_use]
    pub fn new(
        flow: Arc<dyn FlowPostInvocationPort>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            flow,
            missing_context,
        }
    }

    fn inspect_once(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationInspection {
        let Some(security_context) = context.security_context().map(|value| value.as_v1()) else {
            return if self.missing_context.denies() {
                block_with_evidence(self.name(), "authoritative security context is missing")
            } else {
                PostInvocationInspection::without_evidence(PostInvocationVerdict::Allow)
            };
        };
        let Some(request) = context.request else {
            return block_with_evidence(self.name(), "post-invocation request context is missing");
        };
        if context.agent_id.is_none() || context.server_id.is_none() {
            return block_with_evidence(self.name(), "post-invocation identity context is missing");
        }
        let input = FlowPostInvocationInput {
            security_context,
            request,
            response,
        };
        match self.flow.evaluate(&input) {
            Ok(()) => PostInvocationInspection::without_evidence(PostInvocationVerdict::Allow),
            Err(error) => block_with_evidence(self.name(), &format!("flow blocked: {error}")),
        }
    }
}

impl PostInvocationHook for FlowPostInvocationHook {
    fn name(&self) -> &str {
        "chio-flow-post-invocation"
    }

    fn inspect(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationVerdict {
        self.inspect_once(context, response).verdict
    }

    fn inspect_with_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationInspection {
        self.inspect_once(context, response)
    }
}

pub struct RawOutputTripwireHook {
    evaluator: RawOutputTripwireEvaluator,
}

impl RawOutputTripwireHook {
    #[must_use]
    pub fn new(
        detector: Arc<dyn TripwireDetectorPort>,
        publisher: Arc<TripwireEventPublisher>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            evaluator: RawOutputTripwireEvaluator::new(detector, publisher, missing_context),
        }
    }
}

impl PostInvocationHook for RawOutputTripwireHook {
    fn name(&self) -> &str {
        "chio-watermark-tripwire"
    }

    fn inspect(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationVerdict {
        self.evaluator.inspect(context, response).verdict
    }

    fn inspect_with_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationInspection {
        self.evaluator.inspect(context, response)
    }
}

pub(crate) fn block_with_evidence(name: &str, reason: &str) -> PostInvocationInspection {
    PostInvocationInspection::new(
        PostInvocationVerdict::Block(reason.to_string()),
        vec![GuardEvidence {
            guard_name: name.to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        }],
    )
}
