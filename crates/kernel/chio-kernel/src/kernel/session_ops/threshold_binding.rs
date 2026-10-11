//! Bind initial session threshold requests once and retain their owned scope.

use super::*;
use crate::approval::ToolApprovalContext;
use crate::session::PendingThresholdApproval;
use chio_core::capability::governance::GovernedTransactionIntentBody;

const SESSION_CONTEXT_KEY: &str = "chio_session_threshold";
const SESSION_CONTEXT_SCHEMA: &str = "chio.session-threshold-approval.v1";

#[derive(serde::Serialize)]
struct SessionThresholdScope<'a> {
    schema: &'static str,
    session_id: &'a str,
    tenant_id: Option<&'a str>,
}

impl ChioKernel {
    pub(super) fn prepare_session_threshold_intent(
        &self,
        context: &OperationContext,
        request: &mut ToolCallRequest,
        retained: Option<PendingThresholdApproval>,
    ) -> Result<(), KernelError> {
        if let Some(retained) = retained {
            // The continuation claim already compared every immutable wire
            // field. Use the exact held intent, never bind an approved retry.
            request.governed_intent = Some(retained.bound_intent().cloned().ok_or_else(|| {
                denied("pending threshold approval omitted its retained bound intent")
            })?);
            return self.validate_session_threshold_intent(request, Some(&context.session_id));
        }
        self.validate_session_threshold_intent(request, Some(&context.session_id))?;
        if request.approval_token.is_some()
            || !request.approval_tokens.is_empty()
            || request.threshold_approval_proposal.is_some()
            || !matches!(
                request.governed_intent.as_ref().map(|intent| &intent.body),
                Some(GovernedTransactionIntentBody::ToolInvocation)
            )
            || !request.capability.scope.grants.iter().any(|grant| {
                grant.constraints.iter().any(|constraint| {
                    matches!(
                        constraint,
                        Constraint::RequireCumulativeApprovalAbove { .. }
                    )
                })
            })
        {
            return Ok(());
        }
        let matching = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        if !matching.iter().any(|matched| {
            matched.grant.constraints.iter().any(|constraint| {
                matches!(
                    constraint,
                    Constraint::RequireCumulativeApprovalAbove { .. }
                )
            })
        }) {
            return Ok(());
        }
        let scope = self.session_threshold_scope(&context.session_id, &request.agent_id)?;
        let intent = request
            .governed_intent
            .as_mut()
            .ok_or_else(|| denied("threshold approval requires an intent"))?;
        ToolApprovalContext::bind(
            intent,
            &request.capability,
            &request.arguments,
            &request.request_id,
            &self.config.policy_hash,
            &scope,
        )?;
        let object = intent
            .context
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| denied("tool approval context must be an object"))?;
        object.insert(SESSION_CONTEXT_KEY.into(), SESSION_CONTEXT_SCHEMA.into());
        // Binding adds no approval authority. The ordinary pipeline validates
        // the capability and current grants. Required threshold proposal/token
        // admission separately resolves the explicit policy-owned approvers.
        Ok(())
    }

    pub(in crate::kernel) fn validate_session_threshold_intent(
        &self,
        request: &ToolCallRequest,
        session_id: Option<&SessionId>,
    ) -> Result<(), KernelError> {
        let Some(intent) = request.governed_intent.as_ref() else {
            return Ok(());
        };
        let Some(marker) = intent
            .context
            .as_ref()
            .and_then(|value| value.get(SESSION_CONTEXT_KEY))
        else {
            return Ok(());
        };
        if marker.as_str() != Some(SESSION_CONTEXT_SCHEMA) {
            return Err(denied("session threshold approval context is unsupported"));
        }
        let session_id = session_id.ok_or_else(|| {
            denied("session-bound tool approval requires its owned session context")
        })?;
        let scope = self.session_threshold_scope(session_id, &request.agent_id)?;
        ToolApprovalContext::verify(
            intent,
            &request.capability,
            &request.arguments,
            &request.request_id,
            &self.config.policy_hash,
            &scope,
        )
    }

    fn session_threshold_scope(
        &self,
        session_id: &SessionId,
        agent_id: &str,
    ) -> Result<String, KernelError> {
        self.with_session(session_id, |session| {
            if session.agent_id() != agent_id {
                return Err(denied("session threshold approval subject changed"));
            }
            session.ensure_operation_allowed(OperationKind::ToolCall)?;
            // Always retain the owned session identity, including when two
            // authenticated sessions share a tenant and an agent principal.
            let tenant = extract_tenant_id_from_auth_context(&session.auth_context());
            let scope = SessionThresholdScope {
                schema: SESSION_CONTEXT_SCHEMA,
                session_id: session_id.as_str(),
                tenant_id: tenant.as_deref(),
            };
            canonical_json_bytes(&scope)
                .map(|bytes| sha256_hex(&bytes))
                .map_err(|error| {
                    KernelError::GovernedTransactionDenied(format!(
                        "session threshold approval scope is not canonical: {error}"
                    ))
                })
        })
    }
}

fn denied(message: &str) -> KernelError {
    KernelError::GovernedTransactionDenied(message.into())
}
