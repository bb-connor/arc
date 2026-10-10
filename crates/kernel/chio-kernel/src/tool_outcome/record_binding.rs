//! Canonical retained bytes and their original operation binding.
use super::*;

impl ToolOutcomeRecordV1 {
    pub fn validate_canonical_blob(
        &self,
        operation: &AdmissionOperationV1,
        blob: &CanonicalInvocationBlobV1,
    ) -> Result<(), ToolOutcomeError> {
        self.decode_canonical_bytes(operation, blob.bytes())?;
        if blob.blob_ref() != &self.raw_output {
            return Err(ToolOutcomeError::Binding("outcome.raw_invocation_blob"));
        }
        Ok(())
    }

    /// Decode retained bytes once while checking their complete original binding.
    /// The returned value is historical data, never fresh dispatch authority.
    pub fn decode_canonical_bytes(
        &self,
        operation: &AdmissionOperationV1,
        bytes: &[u8],
    ) -> Result<RawInvocationOutcomeV1, ToolOutcomeError> {
        self.validate_against(operation)?;
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(bytes)?;
        let blob_ref = ContentAddressedBlobRefV1::new(digest_bytes("blob_digest", bytes)?);
        if raw.operation_id != self.operation_id
            || raw.request_id != self.request_id
            || raw.dispatch_operation_version != self.dispatch_operation_version
            || raw.dispatch_fence != self.dispatch_fence
            || raw.tool_server != self.tool_server
            || raw.tool_name != self.tool_name
            || raw.provider_attempt != self.provider_attempt
            || raw.transport_terminal_evidence_digest != self.transport_terminal_evidence_digest
            || raw.reported_cost != self.reported_cost
            || blob_ref != self.raw_output
            || u64::try_from(bytes.len()).ok() != Some(self.raw_output_size_bytes)
        {
            return Err(ToolOutcomeError::Binding("outcome.raw_invocation_blob"));
        }
        Ok(raw)
    }
}
