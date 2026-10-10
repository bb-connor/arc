//! A terminal consumption retains and verifies its signed authorization source.

use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedAuthorizationReceiptConsumption {
    binding: AdmissionExactProjectionBindingV1,
    consumption: AuthorizationReceiptConsumption,
    source_receipt: ChioReceipt,
    source_receipt_digest: AdmissionDigest,
    authorization_capability_hash: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

// Decoding this DTO never constructs the sealed proof.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    binding: AdmissionExactProjectionBindingV1,
    consumption: AuthorizationReceiptConsumption,
    source_receipt: ChioReceipt,
    source_receipt_digest: AdmissionDigest,
    authorization_capability_hash: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

impl VerifiedAuthorizationReceiptConsumption {
    /// Verify historical source and consumer receipts against the exact admitted
    /// request. The committing store must independently authenticate the kernel
    /// claimant and live recovery lease; this proof cannot authorize dispatch.
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    pub fn from_signed_source(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        consumer: &ChioReceipt,
        expected_kernel: &PublicKey,
        source: &ChioReceipt,
        consumption: AuthorizationReceiptConsumption,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
    ) -> Result<Self, AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        validate_receipt_projection(
            consumer,
            operation,
            context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            Some((&outcome_id, outcome_version)),
        )?;
        validate_positive_ijson("authorization_outcome_version", outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(&outcome_id)?;
        let expected_tenant = expected_receipt_tenant(operation);
        let request_context = source
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("receipt_context"))
            .ok_or_else(mismatch)?;
        let parameters = &source.action.parameters;
        let payload = parameters.get("operation_payload").ok_or_else(mismatch)?;
        let payload_hash = sha256_hex(
            &canonical_json_bytes(payload)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
        );
        if source.kernel_key != *expected_kernel
            || consumer.kernel_key != *expected_kernel
            || !source.verify_signature().map_err(|_| mismatch())?
            || !consumer.verify_signature().map_err(|_| mismatch())?
            || !source.action.verify_hash().map_err(|_| mismatch())?
            || !consumer.action.verify_hash().map_err(|_| mismatch())?
            || !source.is_allowed()
            || !consumer.is_allowed()
            || source.id == consumer.id
            || source.timestamp > context.trusted_time_unix_ms / 1_000
            || source.capability_id != operation.binding().capability_id().as_str()
            || source.tool_server != consumer.tool_server
            || source.tool_name != consumer.tool_name
            || source.policy_hash != operation.binding().policy_hash().as_str()
            || source.tenant_id.as_deref() != expected_tenant
            || consumption.tenant_id.as_deref() != expected_tenant
            || consumption.authorization_receipt_id != source.id
            || consumption.consumer_receipt_id != consumer.id
            || consumption.request_id != operation.binding().request_id().as_str()
            || request_context
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                != Some(consumption.request_id.as_str())
            || request_context
                .get("authorization_capability_hash")
                .and_then(serde_json::Value::as_str)
                != Some(operation.binding().authorization_capability_hash().as_str())
            || parameters
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                != Some(consumption.session_id.as_str())
            || parameters
                .get("tool_call_id")
                .and_then(serde_json::Value::as_str)
                != Some(consumption.tool_call_id.as_str())
            || parameters
                .get("authorization_parameter_hash")
                .and_then(serde_json::Value::as_str)
                != Some(consumption.parameter_hash.as_str())
            || consumption.parameter_hash != payload_hash
            || payload_hash != operation.binding().action_parameter_hash().as_str()
            || consumer.action.parameter_hash != payload_hash
            || consumption.consumed_at_unix_ms != context.trusted_time_unix_ms
        {
            return Err(mismatch());
        }
        for (field, value) in [
            ("authorization_session", &consumption.session_id),
            ("authorization_tool_call", &consumption.tool_call_id),
        ] {
            AdmissionIdentifier::try_new(field, value.clone())?;
        }
        Ok(Self {
            binding: AdmissionExactProjectionBindingV1::from_verified(
                operation,
                context,
                AdmissionOperationState::Completed,
            )?,
            consumption,
            source_receipt: source.clone(),
            source_receipt_digest: receipt_digest(source)?,
            authorization_capability_hash: operation
                .binding()
                .authorization_capability_hash()
                .clone(),
            outcome_id,
            outcome_version,
        })
    }

    /// Decode retained evidence and rerun source verification. No deserializer
    /// can construct this proof without its receipt and operation bindings.
    pub fn from_canonical_record_verified(
        bytes: &[u8],
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        consumer: &ChioReceipt,
        expected_kernel: &PublicKey,
    ) -> Result<Self, AdmissionOperationError> {
        let wire: Wire = chio_core::canonical::UntrustedJsonText::from_wire(
            bytes,
            MAX_ADMISSION_TERMINAL_RECORD_BYTES,
        )?
        .decode_signed()?;
        let verified = Self::from_signed_source(
            operation,
            context,
            consumer,
            expected_kernel,
            &wire.source_receipt,
            wire.consumption,
            wire.outcome_id,
            wire.outcome_version,
        )?;
        if verified.binding != wire.binding
            || verified.source_receipt_digest != wire.source_receipt_digest
            || verified.authorization_capability_hash != wire.authorization_capability_hash
            || canonical_json_bytes(&verified)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
                != bytes
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(verified)
    }

    pub(in crate::admission_operation) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: &AdmissionDigest,
        outcome_version: u64,
    ) -> Result<(), AdmissionOperationError> {
        self.binding
            .validate_against(operation, context, AdmissionOperationState::Completed)?;
        let expected = Self::from_signed_source(
            operation,
            context,
            receipt.receipt(),
            &receipt.receipt().kernel_key,
            &self.source_receipt,
            self.consumption.clone(),
            outcome_id.clone(),
            outcome_version,
        )?;
        if canonical_json_bytes(self)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
            != canonical_json_bytes(&expected)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn consumption(&self) -> &AuthorizationReceiptConsumption {
        &self.consumption
    }
}
