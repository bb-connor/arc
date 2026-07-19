//! Post-invocation hook pipeline executed after a tool returns output.

use chio_core::receipt::metadata::GuardEvidence;
use chio_core::{capability::scope::ChioScope, AgentId, ServerId};
use serde_json::Value;

use crate::runtime::ToolCallRequest;
use crate::SecurityInvocationContext;

/// Verdict from a post-invocation hook.
#[derive(Debug, Clone)]
pub enum PostInvocationVerdict {
    Allow,
    Block(String),
    Redact(Value),
    Escalate(String),
}

/// Context available to post-invocation hooks after a tool has executed.
#[derive(Clone, Copy, Debug)]
pub struct PostInvocationContext<'a> {
    pub tool_name: &'a str,
    pub request: Option<&'a ToolCallRequest>,
    pub scope: Option<&'a ChioScope>,
    pub agent_id: Option<&'a AgentId>,
    pub server_id: Option<&'a ServerId>,
    pub matched_grant_index: Option<usize>,
    security_context: Option<&'a SecurityInvocationContext>,
}

impl<'a> PostInvocationContext<'a> {
    #[must_use]
    pub fn synthetic(tool_name: &'a str) -> Self {
        Self {
            tool_name,
            request: None,
            scope: None,
            agent_id: None,
            server_id: None,
            matched_grant_index: None,
            security_context: None,
        }
    }

    #[must_use]
    pub fn from_request(request: &'a ToolCallRequest, matched_grant_index: Option<usize>) -> Self {
        Self::from_request_with_security_context(request, matched_grant_index, None)
    }

    #[must_use]
    pub fn from_request_with_security_context(
        request: &'a ToolCallRequest,
        matched_grant_index: Option<usize>,
        security_context: Option<&'a SecurityInvocationContext>,
    ) -> Self {
        Self {
            tool_name: request.tool_name.as_str(),
            request: Some(request),
            scope: Some(&request.capability.scope),
            agent_id: Some(&request.agent_id),
            server_id: Some(&request.server_id),
            matched_grant_index,
            security_context,
        }
    }

    #[must_use]
    pub const fn security_context(&self) -> Option<&'a SecurityInvocationContext> {
        self.security_context
    }
}

/// One request-local post-invocation decision and its evidence.
///
/// Hooks that produce evidence should override
/// [`PostInvocationHook::inspect_with_evidence`] so the verdict and evidence
/// are returned by the same call. The legacy `take_evidence` path remains for
/// existing hooks during migration.
#[derive(Debug, Clone)]
pub struct PostInvocationInspection {
    pub verdict: PostInvocationVerdict,
    pub evidence: Vec<GuardEvidence>,
}

impl PostInvocationInspection {
    #[must_use]
    pub const fn new(verdict: PostInvocationVerdict, evidence: Vec<GuardEvidence>) -> Self {
        Self { verdict, evidence }
    }

    #[must_use]
    pub const fn without_evidence(verdict: PostInvocationVerdict) -> Self {
        Self {
            verdict,
            evidence: Vec::new(),
        }
    }
}

/// A hook that inspects tool responses after invocation.
pub trait PostInvocationHook: Send + Sync {
    fn name(&self) -> &str;

    fn inspect(&self, ctx: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict;

    fn inspect_with_evidence(
        &self,
        ctx: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationInspection {
        let verdict = self.inspect(ctx, response);
        let evidence = self.take_evidence().into_iter().collect();
        PostInvocationInspection::new(verdict, evidence)
    }

    fn take_evidence(&self) -> Option<GuardEvidence> {
        None
    }
}

/// Outcome of running the pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOutcome {
    pub verdict: PostInvocationVerdict,
    pub escalations: Vec<String>,
    pub evidence: Vec<GuardEvidence>,
}

/// Pipeline of post-invocation hooks evaluated in registration order.
pub struct PostInvocationPipeline {
    hooks: Vec<Box<dyn PostInvocationHook>>,
}

impl PostInvocationPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    pub fn add(&mut self, hook: Box<dyn PostInvocationHook>) {
        self.hooks.push(hook);
    }

    pub fn append(&mut self, mut other: Self) {
        self.hooks.append(&mut other.hooks);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.hooks.iter().map(|hook| hook.name()).collect()
    }

    #[must_use]
    pub fn evaluate_with_evidence(&self, tool_name: &str, response: &Value) -> PipelineOutcome {
        let context = PostInvocationContext::synthetic(tool_name);
        self.evaluate_with_context_and_evidence(&context, response)
    }

    #[must_use]
    pub fn evaluate_with_context_and_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PipelineOutcome {
        let mut current_response = response.clone();
        let mut escalations = Vec::new();
        let mut evidence = Vec::new();

        for hook in &self.hooks {
            let inspection = hook.inspect_with_evidence(context, &current_response);
            evidence.extend(inspection.evidence);
            let verdict = inspection.verdict;
            match verdict {
                PostInvocationVerdict::Allow => continue,
                PostInvocationVerdict::Block(reason) => {
                    return PipelineOutcome {
                        verdict: PostInvocationVerdict::Block(reason),
                        escalations,
                        evidence,
                    };
                }
                PostInvocationVerdict::Redact(redacted) => {
                    current_response = redacted;
                }
                PostInvocationVerdict::Escalate(message) => {
                    escalations.push(message);
                }
            }
        }

        let verdict = if current_response != *response {
            PostInvocationVerdict::Redact(current_response)
        } else if !escalations.is_empty() {
            PostInvocationVerdict::Escalate(escalations.join("; "))
        } else {
            PostInvocationVerdict::Allow
        };
        PipelineOutcome {
            verdict,
            escalations,
            evidence,
        }
    }

    #[must_use]
    pub fn evaluate(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> (PostInvocationVerdict, Vec<String>) {
        let outcome = self.evaluate_with_evidence(tool_name, response);
        (outcome.verdict, outcome.escalations)
    }
}

impl Default for PostInvocationPipeline {
    fn default() -> Self {
        Self::new()
    }
}
