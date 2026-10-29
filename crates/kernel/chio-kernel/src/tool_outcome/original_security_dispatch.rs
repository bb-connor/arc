//! Original nonsecret dispatch facts carried through frozen return custody.
use super::*;
use crate::admission_operation::NativeSecurityDispatchRequestBindingV1;
use chio_security_types::ports::RecordId;

const SCHEMA: &str = "chio.original-security-dispatch-binding.v1";

/// Retained data only. Native stores independently verify the original
/// preparation, physical capture and anchored record before accepting it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalSecurityDispatchBindingV1 {
    schema: AdmissionIdentifier,
    dispatch_commitment_id: RecordId,
    live_request_digest: AdmissionDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_dispatch_ledger_digest: Option<AdmissionDigest>,
}

impl OriginalSecurityDispatchBindingV1 {
    pub(crate) fn new(
        binding: &NativeSecurityDispatchRequestBindingV1,
    ) -> Result<Self, ToolOutcomeError> {
        let value = Self {
            schema: AdmissionIdentifier::try_new("original_dispatch_schema", SCHEMA)
                .map_err(|_| invalid())?,
            dispatch_commitment_id: binding.dispatch_commitment_id().clone(),
            live_request_digest: binding.live_request_digest().clone(),
            native_dispatch_ledger_digest: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn from_ledger(
        ledger: &crate::admission_operation::NativeSecurityDispatchLedgerRecordV1,
        context: &crate::SecurityInvocationContext,
    ) -> Result<Self, ToolOutcomeError> {
        let binding = NativeSecurityDispatchRequestBindingV1::from_ledger(ledger, context)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        let mut value = Self::new(&binding)?;
        value.native_dispatch_ledger_digest = Some(ledger.record_digest.clone());
        Ok(value)
    }

    pub(crate) fn bind_native_ledger(
        &mut self,
        ledger: &crate::admission_operation::NativeSecurityDispatchLedgerRecordV1,
        context: &crate::SecurityInvocationContext,
    ) -> Result<(), ToolOutcomeError> {
        let retained = Self::from_ledger(ledger, context)?;
        if self.native_dispatch_ledger_digest.is_some()
            || self.dispatch_commitment_id != retained.dispatch_commitment_id
            || self.live_request_digest != retained.live_request_digest
        {
            return Err(invalid());
        }
        self.native_dispatch_ledger_digest = retained.native_dispatch_ledger_digest;
        Ok(())
    }

    pub fn dispatch_commitment_id(&self) -> &RecordId {
        &self.dispatch_commitment_id
    }

    pub fn live_request_digest(&self) -> &AdmissionDigest {
        &self.live_request_digest
    }

    pub fn native_dispatch_ledger_digest(&self) -> Option<&AdmissionDigest> {
        self.native_dispatch_ledger_digest.as_ref()
    }

    pub(crate) fn validate(&self) -> Result<(), ToolOutcomeError> {
        if self.schema.as_str() != SCHEMA
            || !crate::admission_operation::valid_dispatch_commitment_id(
                &self.dispatch_commitment_id,
            )
        {
            return Err(invalid());
        }
        bounded("raw.original_security_dispatch_binding", self, 1024)?;
        Ok(())
    }
}

impl RawInvocationOutcomeV1 {
    pub fn original_security_dispatch_binding(&self) -> Option<&OriginalSecurityDispatchBindingV1> {
        self.original_security_dispatch_binding.as_deref()
    }

    /// Structural equality only. The physical store independently verifies
    /// this ledger's original capture, serving owner and anchored reference.
    pub fn validate_original_native_dispatch_record(
        &self,
        ledger: &crate::admission_operation::NativeSecurityDispatchLedgerRecordV1,
        context: &crate::SecurityInvocationContext,
        grant_index: u32,
    ) -> Result<(), ToolOutcomeError> {
        self.validate_original_security_dispatch_binding()?;
        let binding = self
            .original_security_dispatch_binding()
            .ok_or_else(invalid)?;
        let original = OriginalSecurityDispatchBindingV1::from_ledger(ledger, context)?;
        if binding != &original
            || self.operation_id != ledger.operation_id
            || self.security_invocation_context.as_ref() != Some(context)
            || self.matched_grant_index != u64::from(grant_index)
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn validate_original_security_dispatch_binding(
        &self,
    ) -> Result<(), ToolOutcomeError> {
        if self.security_release_required != self.original_security_dispatch_binding.is_some() {
            return Err(invalid());
        }
        if let Some(binding) = self.original_security_dispatch_binding.as_ref() {
            binding.validate()?;
            if self.security_invocation_context.is_none() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn invalid() -> ToolOutcomeError {
    ToolOutcomeError::Binding("raw.original_security_dispatch_binding")
}

impl RawInvocationOutcomeV1 {
    // Reconstruction requires complete canonical validation before use.
    pub(super) fn from_persisted_fields(
        value: PersistedRawInvocationOutcomeV1,
    ) -> Result<Self, ToolOutcomeError> {
        if value.schema != RAW_INVOCATION_OUTCOME_SCHEMA {
            return Err(ToolOutcomeError::Invalid("raw.schema"));
        }
        let raw = Self {
            schema: RAW_INVOCATION_OUTCOME_SCHEMA,
            operation_id: value.operation_id,
            request_id: value.request_id,
            dispatch_operation_version: value.dispatch_operation_version,
            dispatch_fence: value.dispatch_fence,
            tool_server: value.tool_server,
            tool_name: value.tool_name,
            provider_attempt: value.provider_attempt,
            transport_terminal_evidence_digest: value.transport_terminal_evidence_digest,
            matched_grant_index: value.matched_grant_index,
            elapsed_millis: value.elapsed_millis,
            stream_limits: value.stream_limits,
            output: value.output,
            reported_cost: value.reported_cost,
            receipt_metadata_snapshot: value.receipt_metadata_snapshot,
            pre_invocation_guard_output: value.pre_invocation_guard_output,
            request_canonical_json: value.request_canonical_json,
            security_invocation_context: value.security_invocation_context,
            federation_context_json: value.federation_context_json,
            security_release_required: value.security_release_required,
            receipt_signing_identity: value.receipt_signing_identity,
            caller_delivery_evidence: value.caller_delivery_evidence,
            original_security_dispatch_binding: value.original_security_dispatch_binding,
        };
        Ok(raw)
    }
}
