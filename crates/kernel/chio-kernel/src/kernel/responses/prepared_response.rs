//! A signed response prepared before terminal publication. This is not evidence
//! of commitment: only the owning obligation's append can discharge a call.

use super::*;

pub(in crate::kernel) struct PreparedResponse {
    response: ToolCallResponse,
    record_mode: ReceiptRecordMode,
    allow_tail: Option<AllowTail>,
}

struct AllowTail {
    memory_action: Option<crate::memory_provenance::MemoryActionKind>,
    nonce: AllowResponseNonce,
}

impl PreparedResponse {
    pub(in crate::kernel) fn terminal(
        response: ToolCallResponse,
        record_mode: ReceiptRecordMode,
    ) -> Self {
        Self {
            response,
            record_mode,
            allow_tail: None,
        }
    }

    pub(super) fn allow(
        response: ToolCallResponse,
        memory_action: Option<crate::memory_provenance::MemoryActionKind>,
        nonce: AllowResponseNonce,
    ) -> Self {
        Self {
            response,
            record_mode: ReceiptRecordMode::WithFederation,
            allow_tail: Some(AllowTail {
                memory_action,
                nonce,
            }),
        }
    }

    pub(in crate::kernel) fn receipt(&self) -> &ChioReceipt {
        &self.response.receipt
    }

    pub(in crate::kernel) fn record_mode(&self) -> ReceiptRecordMode {
        self.record_mode
    }

    pub(in crate::kernel) fn finish_delivery(
        mut self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        let Some(tail) = self.allow_tail.take() else {
            return Ok(self.response);
        };
        let receipt = &self.response.receipt;
        info!(request_id = %request.request_id, tool = %request.tool_name,
            receipt_id = %receipt.id, "tool call allowed");
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            tail.memory_action.as_ref()
        {
            kernel
                .append_memory_provenance_for_write(store, key, request, receipt)
                .map_err(|source| KernelError::DeliveryFailedAfterReceipt {
                    receipt_id: receipt.id.clone(),
                    step: ReceiptDeliveryStep::Provenance,
                    source: Box::new(source),
                })?;
        }
        self.response.execution_nonce = match tail.nonce {
            AllowResponseNonce::Preminted(nonce) => Some(nonce),
            AllowResponseNonce::MintForAllow => kernel
                .mint_execution_nonce_for_allow(request, &request.capability, receipt)
                .map_err(|source| KernelError::DeliveryFailedAfterReceipt {
                    receipt_id: receipt.id.clone(),
                    step: ReceiptDeliveryStep::ExecutionNonce,
                    source: Box::new(source),
                })?,
            AllowResponseNonce::Suppressed => None,
        };
        Ok(self.response)
    }
}

impl ChioKernel {
    /// Compatibility path for callers that do not own a post-effect obligation.
    /// This helper publishes a response but mints no discharge evidence.
    pub(in crate::kernel) fn publish_prepared_response(
        &self,
        request: &ToolCallRequest,
        prepared: PreparedResponse,
    ) -> Result<ToolCallResponse, KernelError> {
        self.record_chio_receipt_with_mode(request, prepared.receipt(), prepared.record_mode())?;
        prepared.finish_delivery(self, request)
    }
}
