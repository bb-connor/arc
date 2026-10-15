//! Nonserialized native selections are data until the owning Kernel binds them.
use super::*;
use crate::admission_operation::AdmissionOperationStoreError;
use chio_security_types::recovery::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCommandContinuationMode {
    SameCurrentGeneration,
    HistoricalGenerationReadOnly,
    ControlOnly,
}

/// A protected physical record key is a different meaning from a wire RecordId.
/// It accepts 1 to 512 Unicode scalar values and at most 2048 UTF-8 bytes,
/// without NUL, the same bounds as the native recovery record catalog.
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryProtectedRecordKey(String);
impl RecoveryProtectedRecordKey {
    pub fn new(value: impl Into<String>) -> Result<Self, AdmissionOperationStoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 2048
            || value.chars().count() > 512
            || value.contains('\0')
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "recovery physical source key refused".into(),
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryGenerationOrdinal(SafeInteger);
impl RecoveryGenerationOrdinal {
    pub fn new(value: u64) -> Result<Self, AdmissionOperationStoreError> {
        if value == 0 {
            return Err(AdmissionOperationStoreError::Invariant(
                "recovery generation identity refused".into(),
            ));
        }
        SafeInteger::new(value).map(Self).map_err(|_| {
            AdmissionOperationStoreError::Invariant("recovery generation identity refused".into())
        })
    }
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// The exact accepted protected workflow source and its immutable generation
/// baseline. ProjectionDigest retains its actual protected-record meaning.
/// No serialization implementation or conversion to SourceDigest is provided.
#[derive(Clone)]
pub struct RecoveryCommandAcceptedGeneration {
    pub record_key: RecoveryProtectedRecordKey,
    pub record_version: SafeInteger,
    pub record_digest: ProjectionDigest,
    pub event_sequence: SafeInteger,
    pub global_commit_sequence: SafeInteger,
    pub initial_record_digest: ProjectionDigest,
    pub initial_global_commit_sequence: SafeInteger,
    pub generation: RecoveryGenerationOrdinal,
    pub step_id: StepId,
    pub continuation_id: ContinuationId,
}

/// Trusted-backend return data. Public construction cannot mint Kernel proof.
/// The native reader authenticates every accepted/initial event and unique
/// global reference, exact original scope and the fixed physical generation.
#[derive(Clone)]
pub struct RecoveryCommandPortSelection {
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub command_id: CommandId,
    pub command_digest: CommandDigest,
    pub accepted_root_revision: SafeInteger,
    pub generation: RecoveryCommandAcceptedGeneration,
    pub mode: RecoveryCommandContinuationMode,
}

pub struct RecoveryCommandPortOutcome {
    pub response: RecoveryCommandResponseV1,
    pub selection: RecoveryCommandPortSelection,
}

/// Store may downgrade a formerly current selection after head advancement.
/// It never upgrades ControlOnly or historical selection to executable.
pub struct RecoveryCommandSelectedWorkflowData {
    pub record: RecoveryWorkflowRecordV1,
    pub effective_mode: RecoveryCommandContinuationMode,
}

#[cfg(test)]
#[path = "command_selection_tests.rs"]
mod tests;
