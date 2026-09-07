//! Preserve threshold waits across all production session tool entrypoints.

use super::*;
use crate::session::{PendingThresholdApproval, SessionError};
use chio_core::capability::governance::ThresholdApprovalProposal;

fn continuation_binding(
    operation: &ToolCallOperation,
    proposal: &ThresholdApprovalProposal,
) -> Result<PendingThresholdApproval, KernelError> {
    // Exhaustive destructuring forces new request fields to choose a binding
    // policy. Only approval evidence may change while this request is pending.
    let ToolCallOperation {
        capability,
        server_id,
        tool_name,
        arguments,
        governed_intent,
        approval_token: _,
        approval_tokens: _,
        threshold_approval_proposal: _,
        supplemental_authorization,
        execution_nonce,
        model_metadata,
        extra_metadata,
    } = operation;
    let immutable_request = (
        "chio.session.threshold-continuation.v1",
        capability,
        server_id,
        tool_name,
        arguments,
        governed_intent,
        supplemental_authorization,
        execution_nonce,
        model_metadata,
        extra_metadata,
    );
    let operation_digest = canonical_json_bytes(&immutable_request)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| {
            KernelError::Internal("threshold continuation request is not canonical".into())
        })?;
    let proposal_digest = proposal.artifact_digest().map_err(|_| {
        KernelError::Internal("threshold continuation proposal is not canonical".into())
    })?;
    Ok(PendingThresholdApproval::new(
        proposal_digest,
        operation_digest,
    ))
}

impl ChioKernel {
    pub(super) fn resume_pending_threshold_request(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<bool, KernelError> {
        self.with_sessions_read(|sessions| {
            let session = session_from_map(sessions, &context.session_id)?;
            let Some(pending) = session.inflight().get(&context.request_id) else {
                return Ok(false);
            };
            if pending.pending_threshold_approval.is_none() {
                return Ok(false);
            }
            let proposal = operation
                .threshold_approval_proposal
                .as_ref()
                .ok_or_else(|| SessionError::ThresholdApprovalRetryMismatch {
                    request_id: context.request_id.clone(),
                })?;
            let binding = continuation_binding(operation, proposal)?;
            session.claim_threshold_approval_retry(context, &binding)?;
            Ok(true)
        })
    }

    pub(super) fn retain_pending_threshold_request(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        response: &ToolCallResponse,
    ) -> Result<bool, KernelError> {
        if response.verdict != Verdict::PendingApproval {
            return Ok(false);
        }
        let Some(ToolCallOutput::Value(value)) = response.output.as_ref() else {
            return Ok(false);
        };
        // This is the kernel's own response after durable proposal persistence,
        // not caller-supplied proposal registration or an authenticated context.
        let proposal: ThresholdApprovalProposal = serde_json::from_value(value.clone())
            .map_err(|_| KernelError::Internal("pending threshold response is malformed".into()))?;
        if proposal.body.request_id != context.request_id.as_str() {
            return Err(KernelError::Internal(
                "pending threshold response changed request ID".into(),
            ));
        }
        let binding = continuation_binding(operation, &proposal)?;
        self.with_sessions_write(|sessions| {
            session_from_map(sessions, &context.session_id)?
                .mark_threshold_approval_pending(context, binding)?;
            Ok(())
        })?;
        Ok(true)
    }
}
