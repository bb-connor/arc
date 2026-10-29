use super::*;

impl ChioKernel {
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    pub(crate) fn build_cancelled_response_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        let prepared = self.prepare_cancelled_response_with_metadata_and_payee_binding(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            verified_payee_binding,
        )?;
        self.publish_prepared_response(request, prepared)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Preparation preserves the existing response input contract."
    )]
    pub(in crate::kernel) fn prepare_cancelled_response_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<PreparedResponse, KernelError> {
        let extra_metadata =
            self.prepare_refusal_receipt_metadata(&request.request_id, extra_metadata)?;
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
            verified_payee_binding,
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Cancelled {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index)?,
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        Ok(PreparedResponse::terminal(
            ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output: None,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Cancelled {
                    reason: reason.to_string(),
                },
                receipt,
                execution_nonce: None,
                denial_code: None,
            },
            ReceiptRecordMode::WithFederation,
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Preparation preserves the existing response input contract."
    )]
    pub(in crate::kernel) fn prepare_incomplete_response_with_output_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<PreparedResponse, KernelError> {
        let extra_metadata =
            self.prepare_refusal_receipt_metadata(&request.request_id, extra_metadata)?;
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(output.as_ref(), None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
            verified_payee_binding,
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index)?,
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        Ok(PreparedResponse::terminal(
            ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Incomplete {
                    reason: reason.to_string(),
                },
                receipt,
                execution_nonce: None,
                denial_code: None,
            },
            ReceiptRecordMode::WithFederation,
        ))
    }
}
