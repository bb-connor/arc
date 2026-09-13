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
        let payload: serde_json::Value = serde_json::from_slice(frame.kernel_context_json())
            .map_err(|_| CallerDeliveryError::Shape)?;
        let not_before_unix_ms = payload
            .get("frozen_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .ok_or(CallerDeliveryError::Binding)?;
        let request = original.request_for_revalidation();
        let executor = original
            .authority_profile()
            .and_then(|profile| profile.caller_executor())
            .ok_or(CallerDeliveryError::Binding)?;
        let expires_at_unix_ms = u64::try_from(nonce.signed_nonce().expires_at())
            .ok()
            .map(|until| until.min(request.capability.expires_at))
            .and_then(|until| until.checked_mul(1000))
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
