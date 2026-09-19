//! Borrow the actual finalization artifacts without minting replay authority.
use super::*;

/// Exact post-guard output and signing preimage presented to the live release
/// owner. The kernel validates its outcome, evaluation and dispatch binding
/// before calling the owner. No public constructor, cloning or decoding can
/// recreate this context. It is not a successful release acknowledgement.
///
/// The security context is the admitted identity, not a fresh flow observation.
/// Native writers must still check current state, the operation lease and owner
/// fence. Stream signing preimages contain chunk digests, not payload bytes:
/// classifiers must inspect `output()`, not classify `signing_preimage()`.
pub struct DurableSecurityReleaseContext<'a> {
    record: &'a SecurityReleaseRecordV1,
    operation: &'a AdmissionOperationV1,
    outcome: &'a ToolOutcomeRecordV1,
    evaluation: &'a PostReturnEvaluationRecordV1,
    request_canonical_json: &'a str,
    security_context: &'a crate::SecurityInvocationContext,
    output: &'a crate::ToolCallOutput,
    resolved_output: &'a [u8],
}

impl<'a> DurableSecurityReleaseContext<'a> {
    pub(super) fn new(
        record: &'a SecurityReleaseRecordV1,
        artifacts: &SecurityReleaseArtifacts<'a>,
    ) -> Result<Self, ToolOutcomeError> {
        record.validate_against(
            artifacts.operation,
            artifacts.raw,
            artifacts.outcome,
            artifacts.evaluation,
        )?;
        if artifacts.operation.state() != AdmissionOperationState::Finalizing {
            return Err(ToolOutcomeError::Binding("security_release.live_operation"));
        }
        let (expected, size) = artifacts
            .outcome
            .resolved_output_ref()
            .ok_or(ToolOutcomeError::Binding("security_release.output"))?;
        if artifacts.resolved_output.len() > MAX_RESOLVED_OUTPUT_BYTES
            || u64::try_from(artifacts.resolved_output.len()).ok() != Some(size)
            || &digest_bytes("security_release.output", artifacts.resolved_output)?
                != expected.digest()
        {
            return Err(ToolOutcomeError::Binding(
                "security_release.output_preimage",
            ));
        }
        let content =
            crate::receipt_support::receipt_content_for_output(Some(artifacts.output), None)
                .map_err(|_| ToolOutcomeError::Binding("security_release.output_encoding"))?;
        if content.canonical_content != artifacts.resolved_output {
            return Err(ToolOutcomeError::Binding("security_release.output_payload"));
        }
        Ok(Self {
            record,
            operation: artifacts.operation,
            outcome: artifacts.outcome,
            evaluation: artifacts.evaluation,
            request_canonical_json: artifacts
                .raw
                .request_canonical_json
                .as_deref()
                .ok_or(ToolOutcomeError::Binding("security_release.request"))?,
            security_context: artifacts
                .raw
                .security_invocation_context()
                .ok_or(ToolOutcomeError::Binding("security_release.context"))?,
            output: artifacts.output,
            resolved_output: artifacts.resolved_output,
        })
    }

    pub fn operation(&self) -> &AdmissionOperationV1 {
        self.operation
    }

    pub fn outcome(&self) -> &ToolOutcomeRecordV1 {
        self.outcome
    }

    pub fn evaluation(&self) -> &PostReturnEvaluationRecordV1 {
        self.evaluation
    }

    pub fn request_canonical_json(&self) -> &str {
        self.request_canonical_json
    }

    pub fn security_context(&self) -> &crate::SecurityInvocationContext {
        self.security_context
    }

    pub fn dispatch_commitment_id(&self) -> &chio_security_types::ports::RecordId {
        &self.record.dispatch_commitment_id
    }

    pub fn output(&self) -> &crate::ToolCallOutput {
        self.output
    }

    pub fn signing_preimage(&self) -> &[u8] {
        self.resolved_output
    }
}

impl std::fmt::Debug for DurableSecurityReleaseContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableSecurityReleaseContext")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
