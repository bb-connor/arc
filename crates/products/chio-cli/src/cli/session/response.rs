use super::*;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResponseProjectionError {
    #[error("pending approval response has an invalid lifecycle or output shape")]
    Shape,
    #[error("pending approval response contains an invalid proposal")]
    Proposal,
    #[error("pending approval response does not preserve its request or receipt binding")]
    Binding,
}

pub(crate) fn tool_response_messages(
    request_id: String,
    response: chio_kernel::ToolCallResponse,
) -> Result<Vec<KernelMessage>, ResponseProjectionError> {
    if response.verdict == chio_kernel::Verdict::PendingApproval {
        let proposal = pending_proposal(&request_id, &response)?;
        return Ok(vec![KernelMessage::ToolCallResponse {
            id: request_id,
            result: ToolCallResult::PendingApproval { proposal },
            receipt: Box::new(response.receipt),
            execution_nonce: None,
        }]);
    }
    let execution_nonce = response.execution_nonce.clone();
    let mut messages = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(ToolCallStream { chunks })) => chunks
            .iter()
            .enumerate()
            .map(|(chunk_index, chunk)| KernelMessage::ToolCallChunk {
                id: request_id.clone(),
                chunk_index: chunk_index as u64,
                data: chunk.data.clone(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let chunks_received = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(stream)) => stream.chunk_count(),
        _ => 0,
    };

    let result = match (
        response.verdict,
        response.terminal_state.clone(),
        response.output,
    ) {
        (chio_kernel::Verdict::Allow, _, Some(ToolCallOutput::Value(value))) => {
            ToolCallResult::Ok { value }
        }
        (chio_kernel::Verdict::Allow, _, Some(ToolCallOutput::Stream(_))) => {
            ToolCallResult::StreamComplete {
                total_chunks: chunks_received,
            }
        }
        (chio_kernel::Verdict::Deny, OperationTerminalState::Cancelled { reason }, _) => {
            ToolCallResult::Cancelled {
                reason,
                chunks_received,
            }
        }
        (chio_kernel::Verdict::Deny, OperationTerminalState::Incomplete { reason }, _) => {
            ToolCallResult::Incomplete {
                reason,
                chunks_received,
            }
        }
        (chio_kernel::Verdict::Deny, OperationTerminalState::Completed, _) => ToolCallResult::Err {
            error: ToolCallError::PolicyDenied {
                guard: match response.receipt.decision.as_ref() {
                    Some(chio_core::receipt::decision::Decision::Deny { guard, .. }) => {
                        guard.clone()
                    }
                    _ => "kernel".to_string(),
                },
                reason: response
                    .reason
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        },
        (chio_kernel::Verdict::Allow, _, None) => ToolCallResult::Ok {
            value: serde_json::Value::Null,
        },
        (chio_kernel::Verdict::PendingApproval, _, _) => {
            return Err(ResponseProjectionError::Shape);
        }
    };

    messages.push(KernelMessage::ToolCallResponse {
        id: request_id,
        result,
        receipt: Box::new(response.receipt),
        execution_nonce,
    });
    Ok(messages)
}

fn pending_proposal(
    request_id: &str,
    response: &chio_kernel::ToolCallResponse,
) -> Result<
    Box<chio_core::capability::governance::ThresholdApprovalProposal>,
    ResponseProjectionError,
> {
    use ResponseProjectionError::{Binding, Proposal, Shape};

    if !matches!(&response.terminal_state, OperationTerminalState::Incomplete { reason } if reason == "approval_required")
        || response.execution_nonce.is_some()
    {
        return Err(Shape);
    }
    let Some(ToolCallOutput::Value(value)) = &response.output else {
        return Err(Shape);
    };
    let proposal: chio_core::capability::governance::ThresholdApprovalProposal =
        serde_json::from_value(value.clone()).map_err(|_| Proposal)?;
    proposal.body.validate().map_err(|_| Proposal)?;
    let original = chio_core::canonical_json_bytes(value).map_err(|_| Proposal)?;
    let projected = chio_core::canonical_json_bytes(&proposal).map_err(|_| Proposal)?;
    // Projection preserves the kernel's artifact, not a normalized replacement.
    // Authority and freshness are checked by the collector and on kernel retry.
    if original != projected
        || response.request_id != request_id
        || proposal.body.request_id != request_id
        || response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/receipt_context/request_id"))
            .and_then(serde_json::Value::as_str)
            != Some(request_id)
        || response.receipt.content_hash != chio_core::sha256_hex(&original)
    {
        return Err(Binding);
    }
    Ok(Box::new(proposal))
}
