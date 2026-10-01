//! Session-bound nested invocation. Proofs are untrusted request inputs, not permits.
use super::*;
use crate::dpop::DpopProof;
use crate::execution_nonce::SignedExecutionNonce;
use chio_core_types::SignedDeclassificationGrant;

/// Additional signed request artifacts for a session-scoped nested tool call.
///
/// These inputs pass through the same capability, freshness, replay and security
/// policy checks as ordinary tool requests. Supplying an artifact never grants
/// dispatch authority or enables a profile that the configured kernel rejects.
/// Execution nonces and governed approvals remain part of `ToolCallOperation`.
#[derive(Clone, Default)]
pub struct NestedToolCallProofs {
    /// Proof of possession bound to the capability, agent and exact tool action.
    pub dpop_proof: Option<DpopProof>,
    /// One-shot declassification request, subject to the configured flow policy.
    pub declassification_grant: Option<SignedDeclassificationGrant>,
}

impl std::fmt::Debug for NestedToolCallProofs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NestedToolCallProofs")
            .field("has_dpop_proof", &self.dpop_proof.is_some())
            .field(
                "has_declassification_grant",
                &self.declassification_grant.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ChioKernel {
    /// Evaluate a session-scoped tool call while allowing the target tool server to proxy
    /// negotiated nested flows back through a client transport owned by the edge.
    pub fn evaluate_tool_call_operation_with_nested_flow_client<C: NestedFlowClient>(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
            context,
            operation,
            client,
            NestedToolCallProofs::default(),
        )
    }

    /// Evaluate a nested tool call with explicitly supplied, untrusted proofs.
    /// All session, credential and dispatch checks remain mandatory.
    pub fn evaluate_tool_call_operation_with_nested_flow_client_and_proofs<C: NestedFlowClient>(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
        proofs: NestedToolCallProofs,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        if let Some(response) = self.reject_conflicting_session_authorization(context, operation)? {
            return Ok(response);
        }
        let execution_nonce = parse_tool_call_operation_execution_nonce(operation)?;
        self.begin_or_resume_tool_request(context, operation, execution_nonce.as_ref())?;

        let request = nested_tool_request(context, operation, execution_nonce, proofs);

        // Once begun, resolution failures must use the same terminal cleanup
        // as evaluation failures. Returning early would leak in-flight state.
        let result = self
            .resolve_security_invocation_context(context, operation)
            .and_then(|security_context| {
                self.evaluate_tool_call_with_nested_flow_client_and_security_context(
                    context,
                    &request,
                    client,
                    operation.extra_metadata.clone(),
                    security_context.as_ref(),
                )
            });
        let terminal_state = match &result {
            Ok(response) => response.terminal_state.clone(),
            Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == &context.request_id =>
            {
                self.with_session_mut(&context.session_id, |session| {
                    session.request_cancellation(&context.request_id)?;
                    Ok(())
                })?;
                OperationTerminalState::Cancelled {
                    reason: reason.clone(),
                }
            }
            _ => OperationTerminalState::Completed,
        };
        self.finish_session_tool_request(
            context,
            Some(operation),
            result.as_ref().ok(),
            terminal_state,
        )?;
        result
    }

    /// Async-native variant for hosts that already run inside a Tokio runtime.
    ///
    /// This path avoids the synchronous dispatch bridge, so current-thread
    /// runtimes do not convert nested-flow tool calls into bridge errors. The
    /// synchronous entrypoint remains for blocking edges and still fails before
    /// side effects when a current-thread runtime is entered.
    pub async fn evaluate_tool_call_operation_with_nested_flow_client_async<C: NestedFlowClient>(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
            context,
            operation,
            client,
            NestedToolCallProofs::default(),
        )
        .await
    }

    /// Async-native nested invocation with the same proof validation as the
    /// blocking entrypoint. No synchronous dispatch bridge is entered.
    pub async fn evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async<
        C: NestedFlowClient,
    >(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
        proofs: NestedToolCallProofs,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        if let Some(response) = self.reject_conflicting_session_authorization(context, operation)? {
            return Ok(response);
        }
        let execution_nonce = parse_tool_call_operation_execution_nonce(operation)?;
        self.begin_or_resume_tool_request(context, operation, execution_nonce.as_ref())?;

        let request = nested_tool_request(context, operation, execution_nonce, proofs);

        let result = match self.resolve_security_invocation_context(context, operation) {
            Ok(security_context) => {
                self.evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    context,
                    &request,
                    client,
                    operation.extra_metadata.clone(),
                    security_context.as_ref(),
                )
                .await
            }
            Err(error) => Err(error),
        };
        let terminal_state = match &result {
            Ok(response) => response.terminal_state.clone(),
            Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == &context.request_id =>
            {
                self.with_session_mut(&context.session_id, |session| {
                    session.request_cancellation(&context.request_id)?;
                    Ok(())
                })?;
                OperationTerminalState::Cancelled {
                    reason: reason.clone(),
                }
            }
            _ => OperationTerminalState::Completed,
        };
        self.finish_session_tool_request(
            context,
            Some(operation),
            result.as_ref().ok(),
            terminal_state,
        )?;
        result
    }
}

fn nested_tool_request(
    context: &OperationContext,
    operation: &ToolCallOperation,
    execution_nonce: Option<SignedExecutionNonce>,
    proofs: NestedToolCallProofs,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: context.request_id.to_string(),
        capability: operation.capability.clone(),
        tool_name: operation.tool_name.clone(),
        server_id: operation.server_id.clone(),
        agent_id: context.agent_id.clone(),
        arguments: operation.arguments.clone(),
        dpop_proof: proofs.dpop_proof,
        execution_nonce,
        governed_intent: operation.governed_intent.clone(),
        approval_token: operation.approval_token.clone(),
        approval_tokens: operation.approval_tokens.clone(),
        threshold_approval_proposal: operation.threshold_approval_proposal.clone(),
        supplemental_authorization: operation.supplemental_authorization.clone(),
        model_metadata: operation.model_metadata.clone(),
        federated_origin_kernel_id: None,
        declassification_grant: proofs.declassification_grant,
    }
}
