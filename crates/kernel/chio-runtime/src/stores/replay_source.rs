use super::SqliteRuntimeOrchestrationStore;
use crate::{wrap_runtime, ChioRuntimeError, RuntimeReplaySourceBinding, RuntimeReplaySourceSeal};
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, RuntimeReplaySourcePort,
    RuntimeReplaySourceSnapshotV1,
};

impl SqliteRuntimeOrchestrationStore {
    /// Observe an unsealed source without reserving resources or authenticating
    /// destination authority. The qualified destination must pin these data.
    pub fn preview_legacy_replay_source(
        &self,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<RuntimeReplaySourceSnapshotV1, ChioRuntimeError> {
        wrap_runtime(self.inner.preview_legacy_replay_source(binding))
    }

    /// Retire legacy writers only if the source still matches the exact pinned
    /// candidate. This does not import markers or activate the destination.
    pub fn seal_expected_legacy_replay_source(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
        wrap_runtime(self.inner.seal_expected_legacy_replay_source(expected))
    }

    /// Permanently disable legacy replay mutations and retain the complete source inventory.
    /// This does not activate a destination authority or authorize runtime dispatch.
    pub fn seal_legacy_replay_source(
        &self,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
        wrap_runtime(self.inner.seal_legacy_replay_source(binding))
    }

    pub fn load_legacy_replay_source_seal(
        &self,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<Option<RuntimeReplaySourceSeal>, ChioRuntimeError> {
        wrap_runtime(self.inner.load_legacy_replay_source_seal(binding))
    }

    /// Revalidate live source contents, barriers and file identity against an expected seal.
    /// The expected artifact must be retained independently for continuity checking.
    pub fn verify_legacy_replay_source_seal(
        &self,
        expected: &RuntimeReplaySourceSeal,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.verify_legacy_replay_source_seal(expected))
    }
}

impl RuntimeReplaySourcePort for SqliteRuntimeOrchestrationStore {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        RuntimeReplaySourcePort::preview(
            &self.inner,
            source_id,
            runtime_authority_id,
            destination_authority_id,
        )
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        RuntimeReplaySourcePort::seal_exact(&self.inner, expected)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        RuntimeReplaySourcePort::verify_exact(&self.inner, expected)
    }
}
