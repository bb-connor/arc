//! Durable evidence of final release, separate from output evaluation and
//! monetary settlement. Decoding evidence never reconstructs a live owner.

use super::*;

mod context;
pub use context::DurableSecurityReleaseContext;

pub(crate) struct SecurityReleaseArtifacts<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub raw: &'a RawInvocationOutcomeV1,
    pub outcome: &'a ToolOutcomeRecordV1,
    pub evaluation: &'a PostReturnEvaluationRecordV1,
    pub output: &'a crate::ToolCallOutput,
    pub resolved_output: &'a [u8],
}

#[cfg(any(test, feature = "admission-test-support"))]
impl SecurityReleaseArtifacts<'_> {
    pub(crate) fn inspect_for_test<T>(
        &self,
        inspect: impl FnOnce(&DurableSecurityReleaseContext<'_>) -> T,
    ) -> Result<T, ToolOutcomeError> {
        let record = SecurityReleaseRecordV1::pending(
            self,
            self.outcome.recording_fence.clone(),
            crate::kernel::current_unix_timestamp_ms().max(self.evaluation.trusted_time_unix_ms()),
        )?;
        let context = DurableSecurityReleaseContext::new(&record, self)?;
        Ok(inspect(&context))
    }
}

const SCHEMA: &str = "chio.security-release-checkpoint.v1";
const MAX_BYTES: usize = 8 * 1024;

/// Structural record data. Its authority comes only from the fenced, anchored
/// outcome store and exact invocation, evaluation and dispatch bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityReleaseRecordV1 {
    schema: String,
    operation_id: AdmissionOperationId,
    request_binding_hash: AdmissionDigest,
    dispatch_commitment_id: chio_security_types::ports::RecordId,
    outcome_id: AdmissionDigest,
    raw_output_digest: AdmissionDigest,
    evaluation_id: AdmissionDigest,
    evaluation_lifecycle_digest: AdmissionDigest,
    resolved_output_digest: AdmissionDigest,
    acknowledged_at_unix_ms: u64,
    store_fence: StoreMutationFence,
}

/// Only the kernel's successful live release path can construct this value.
/// It is neither serializable nor cloneable and cannot be restored from a DTO.
pub struct AcknowledgedSecurityReleaseV1 {
    record: SecurityReleaseRecordV1,
}

impl AcknowledgedSecurityReleaseV1 {
    pub(crate) fn acknowledge(
        permit: crate::kernel::SecurityRequestLifecycleHandle,
        artifacts: SecurityReleaseArtifacts<'_>,
        store_fence: StoreMutationFence,
        acknowledged_at_unix_ms: u64,
        prepare_output: impl FnOnce(
            &DurableSecurityReleaseContext<'_>,
        ) -> Result<(), crate::KernelError>,
    ) -> Result<Self, crate::KernelError> {
        let mut record =
            SecurityReleaseRecordV1::pending(&artifacts, store_fence, acknowledged_at_unix_ms)
                .map_err(|error| {
                    crate::KernelError::SecurityDispatchOutcomeRecoveryRequired(error.to_string())
                })?;
        let context = DurableSecurityReleaseContext::new(&record, &artifacts).map_err(|error| {
            crate::KernelError::SecurityDispatchOutcomeRecoveryRequired(error.to_string())
        })?;
        permit.validate_release_context(&context)?;
        prepare_output(&context)?;
        permit.ensure_final_release_for(&context)?;
        // A native callback can outlive the selected evaluation time. Lease
        // validation must see the time of its acknowledgement, not its start.
        record.acknowledged_at_unix_ms =
            acknowledged_at_unix_ms.max(crate::kernel::current_unix_timestamp_ms());
        record.canonical_bytes().map_err(|error| {
            crate::KernelError::SecurityDispatchOutcomeRecoveryRequired(error.to_string())
        })?;
        Ok(Self { record })
    }

    pub fn record(&self) -> &SecurityReleaseRecordV1 {
        &self.record
    }
}

impl SecurityReleaseRecordV1 {
    fn pending(
        artifacts: &SecurityReleaseArtifacts<'_>,
        store_fence: StoreMutationFence,
        acknowledged_at_unix_ms: u64,
    ) -> Result<Self, ToolOutcomeError> {
        let SecurityReleaseArtifacts {
            operation,
            raw,
            outcome,
            evaluation,
            ..
        } = artifacts;
        Ok(Self {
            schema: SCHEMA.into(),
            operation_id: operation.binding().operation_id().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            dispatch_commitment_id: raw.security_dispatch_commitment_id()?,
            outcome_id: outcome.outcome_id().clone(),
            raw_output_digest: outcome.raw_output_digest().clone(),
            evaluation_id: evaluation.evaluation_id().clone(),
            evaluation_lifecycle_digest: evaluation.lifecycle_digest.clone(),
            resolved_output_digest: outcome
                .resolved_output_ref()
                .ok_or(ToolOutcomeError::Binding("security_release.output"))?
                .0
                .digest()
                .clone(),
            acknowledged_at_unix_ms,
            store_fence,
        })
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }
    pub fn acknowledged_at_unix_ms(&self) -> u64 {
        self.acknowledged_at_unix_ms
    }
    pub fn store_fence(&self) -> &StoreMutationFence {
        &self.store_fence
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ToolOutcomeError> {
        if self.schema != SCHEMA {
            return Err(ToolOutcomeError::Invalid("security_release.schema"));
        }
        positive(
            "security_release.acknowledged_at",
            self.acknowledged_at_unix_ms,
        )?;
        validate_store_fence(&self.store_fence)?;
        bounded("security_release.record", self, MAX_BYTES)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ToolOutcomeError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(ToolOutcomeError::Invalid("security_release.record_size"));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        if record.canonical_bytes()? != bytes {
            return Err(ToolOutcomeError::Invalid(
                "security_release.noncanonical_record",
            ));
        }
        Ok(record)
    }

    pub fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        raw: &RawInvocationOutcomeV1,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<(), ToolOutcomeError> {
        outcome.validate_canonical_blob(operation, &raw.canonical_blob()?)?;
        if !raw.requires_security_release()?
            || self.dispatch_commitment_id != raw.security_dispatch_commitment_id()?
        {
            return Err(ToolOutcomeError::Binding("security_release.dispatch"));
        }
        self.validate_retained_against(operation, outcome, evaluation)
    }

    /// Verify retained identities after authorized raw-payload compaction. This
    /// is not a substitute for raw binding checks while the payload exists.
    pub fn validate_retained_against(
        &self,
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<(), ToolOutcomeError> {
        self.canonical_bytes()?;
        outcome.validate_against(operation)?;
        evaluation.validate_against(operation, outcome)?;
        if self.operation_id != *operation.binding().operation_id()
            || self.request_binding_hash != *operation.binding().request_binding_hash()
            || self.outcome_id != *outcome.outcome_id()
            || self.raw_output_digest != *outcome.raw_output_digest()
            || self.evaluation_id != *evaluation.evaluation_id()
            || self.evaluation_lifecycle_digest != evaluation.lifecycle_digest
            || !matches!(
                evaluation.state(),
                PostReturnEvaluationStateV1::Resolved { .. }
            )
            || outcome
                .resolved_output_ref()
                .map(|(output, _)| output.digest())
                != Some(&self.resolved_output_digest)
            || self.acknowledged_at_unix_ms < outcome.recorded_at_unix_ms()
            || self.acknowledged_at_unix_ms < evaluation.trusted_time_unix_ms()
        {
            return Err(ToolOutcomeError::Binding("security_release.records"));
        }
        validate_successor_fence(&outcome.recording_fence, &self.store_fence)?;
        Ok(())
    }
}

impl RawInvocationOutcomeV1 {
    pub(crate) fn security_dispatch_commitment_id(
        &self,
    ) -> Result<chio_security_types::ports::RecordId, ToolOutcomeError> {
        let request = self
            .request_canonical_json
            .as_ref()
            .ok_or(ToolOutcomeError::Binding("security_release.request"))?;
        let context = self
            .security_invocation_context
            .as_ref()
            .ok_or(ToolOutcomeError::Binding("security_release.context"))?;
        crate::kernel::derive_security_dispatch_commitment_id(request.as_bytes(), context)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))
    }
}
