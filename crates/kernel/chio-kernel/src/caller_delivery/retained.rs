//! Independent original-admission authentication for native output recovery.
use super::*;
use crate::admission_operation::{
    AdmissionCallerDispatchContextV1, AdmissionExecutionNonceReservationV1, AdmissionOperationV1,
    NativeCallerReleaseCustodyV1, RetainedToolAdmissionRequestV1,
};

impl CallerDeliveryEvidenceV1 {
    /// All arguments must be independently read from the original fenced
    /// authority. This validates historical delivery, never fresh execution.
    pub fn validate_native_original(
        &self,
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        nonce: &AdmissionExecutionNonceReservationV1,
        frame: &AdmissionCallerDispatchContextV1,
    ) -> Result<NativeCallerReleaseCustodyV1, CallerDeliveryError> {
        let invalid = |_| CallerDeliveryError::Binding;
        let frame = AdmissionCallerDispatchContextV1::from_canonical_bytes(
            frame.canonical_bytes(),
            operation,
            original,
        )
        .map_err(invalid)?;
        let custody = frame
            .native_release_custody(operation, original)
            .map_err(invalid)?
            .ok_or(CallerDeliveryError::Binding)?;
        let payload: serde_json::Value = chio_core::canonical::UntrustedJsonText::from_wire(
            frame.kernel_context_json(),
            crate::admission_operation::AdmissionCallerDispatchContextV1::MAX_KERNEL_CONTEXT_BYTES,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|_| CallerDeliveryError::Shape)?;
        let not_before_unix_ms = payload
            .get("frozen_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .ok_or(CallerDeliveryError::Binding)?;
        let request = original.request_for_revalidation();
        let executor = original
            .authority_profile()
            .caller_executor()
            .ok_or(CallerDeliveryError::Binding)?;
        let expires_at_unix_ms = original_nonce_horizon(operation, nonce)?
            .min(request.capability.expires_at)
            .checked_mul(1000)
            .ok_or(CallerDeliveryError::Binding)?
            .min(custody.valid_until_unix_ms());
        let digest = |field, bytes: &[u8]| {
            AdmissionDigest::try_new(field, sha256_hex(bytes))
                .map_err(|_| CallerDeliveryError::Binding)
        };
        let expected = CallerDispatchAuthorizationBodyV1 {
            schema: CALLER_DISPATCH_AUTHORIZATION_SCHEMA.into(),
            kernel_public_key: nonce.issuer().clone(),
            executor: executor.clone(),
            invocation: CallerInvocationBindingV1 {
                operation_id: operation.binding().operation_id().clone(),
                request_id: operation.binding().request_id().clone(),
                request_binding_hash: operation.binding().request_binding_hash().clone(),
                capability_id: operation.binding().capability_id().clone(),
                capability_digest: digest(
                    "capability_digest",
                    &canonical_json_bytes(&request.capability)
                        .map_err(|_| CallerDeliveryError::Shape)?,
                )?,
                server_id: AdmissionIdentifier::try_new("server_id", request.server_id.clone())
                    .map_err(|_| CallerDeliveryError::Binding)?,
                tool_name: AdmissionIdentifier::try_new("tool_name", request.tool_name.clone())
                    .map_err(|_| CallerDeliveryError::Binding)?,
                parameters_digest: operation.binding().action_parameter_hash().clone(),
            },
            committed: CallerCommittedDispatchV1 {
                execution_nonce_id: operation
                    .execution_nonce_id()
                    .cloned()
                    .ok_or(CallerDeliveryError::Binding)?,
                budget_hold_id: operation
                    .budget_hold_id()
                    .cloned()
                    .ok_or(CallerDeliveryError::Binding)?,
                dispatch_commit: operation
                    .dispatch_commit()
                    .cloned()
                    .ok_or(CallerDeliveryError::Binding)?,
                frozen_context_digest: frame.digest().clone(),
            },
            not_before_unix_ms,
            expires_at_unix_ms,
        };
        if self.authorization.authorization != expected {
            return Err(CallerDeliveryError::Binding);
        }
        self.report.verify(
            &self.authorization,
            nonce.issuer(),
            executor,
            &expected.invocation,
        )?;
        Ok(custody)
    }
}

/// Exclusive dispatch horizon, in seconds, that the original nonce imposed.
/// An operation retaining its own threshold proposal bound that nonce when the
/// proposal was created, so native capture froze the approval deadline in its
/// place. Every other nonce still caps delivery at its own expiry.
fn original_nonce_horizon(
    operation: &AdmissionOperationV1,
    nonce: &AdmissionExecutionNonceReservationV1,
) -> Result<u64, CallerDeliveryError> {
    let signed = nonce.signed_nonce();
    let Some(proposal) = operation.threshold_proposal() else {
        return u64::try_from(signed.expires_at()).map_err(|_| CallerDeliveryError::Binding);
    };
    let bound_at = i64::try_from(proposal.body.proposal_created_at)
        .map_err(|_| CallerDeliveryError::Binding)?;
    if !operation.binding().participant_requirements().approval
        || proposal.body.proposal_id != operation.binding().operation_id().as_str()
        || operation.execution_nonce_id() != Some(nonce.nonce_id())
        || bound_at < signed.nonce.issued_at
        || bound_at >= signed.expires_at()
    {
        return Err(CallerDeliveryError::Binding);
    }
    Ok(proposal.body.proposal_deadline)
}
