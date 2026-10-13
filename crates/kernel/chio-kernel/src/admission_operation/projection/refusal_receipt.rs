use super::*;

impl VerifiedAdmissionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_kernel_verified_refusal(
        receipt: ChioReceipt,
        expected_kernel_public_key: &PublicKey,
        expected_decision: &Decision,
        expected_tool_server: &str,
        expected_tool_name: &str,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
    ) -> Result<Self, AdmissionOperationError> {
        let compensation_status = match projected_state {
            AdmissionOperationState::CompensatedBeforeDispatch => {
                AdmissionCompensationStatus::CompensatedBeforeDispatch
            }
            AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                AdmissionCompensationStatus::NotCompensated
            }
            _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
        };
        validate_refusal_receipt(&receipt)?;
        let null_digest = AdmissionDigest::try_new("null_output_digest", sha256_hex(b"null"))?;
        Self::qualify(
            receipt,
            expected_kernel_public_key,
            expected_decision,
            expected_tool_server,
            expected_tool_name,
            operation.binding.action_parameter_hash(),
            &null_digest,
            operation,
            context,
            projected_state,
            compensation_status,
            None,
        )
    }
}

pub(super) fn validate_refusal_receipt(
    receipt: &ChioReceipt,
) -> Result<(), AdmissionOperationError> {
    let decision_valid = match receipt.decision.as_ref() {
        Some(Decision::Deny { guard, .. }) => guard == "kernel",
        Some(Decision::Cancelled { .. }) => true,
        _ => false,
    };
    if !decision_valid || receipt.content_hash != sha256_hex(b"null") {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}
