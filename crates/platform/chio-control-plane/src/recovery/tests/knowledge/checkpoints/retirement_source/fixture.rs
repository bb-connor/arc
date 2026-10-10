//! Current public writers and connection-local fail-only controls.
use super::*;

pub(super) struct RetainedCheckpoint {
    pub(super) checkpoint: LabeledCheckpointV1,
    pub(super) seal: ArtifactBlobSealV1,
    pub(super) key: String,
}

impl RetainedCheckpoint {
    pub(super) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.checkpoint.artifacts.as_slice()[0]
    }
}

pub(super) struct RetirementFixture {
    pub(super) knowledge: KnowledgeFixture,
    pub(super) own: RetainedCheckpoint,
    pub(super) foreign: RetainedCheckpoint,
}

impl RetirementFixture {
    pub(super) fn new() -> TestResult<Self> {
        let knowledge = KnowledgeFixture::new()?;
        let own = Self::checkpoint(&knowledge, "job", b"own-checkpoint")?;
        let foreign = Self::checkpoint(&knowledge, "job:1", b"foreign-checkpoint")?;
        assert_ne!(format!("{}:1", own.key), foreign.key);
        Ok(Self {
            knowledge,
            own,
            foreign,
        })
    }

    fn checkpoint(f: &KnowledgeFixture, id: &str, bytes: &[u8]) -> TestResult<RetainedCheckpoint> {
        let reference = f.publish(id, bytes)?;
        let checkpoint = f.runtime.checkpoint(
            &f.f.control,
            &CheckpointId::new(id)?,
            0,
            std::slice::from_ref(&reference),
            &[],
        )?;
        let handle = f.runtime.handle(
            &f.f.control,
            &reference,
            &ArtifactRecipientId::new("agent-root")?,
        )?;
        let (record, _) =
            f.f.authority
                .admission_operation_store()
                .prepare_artifact_read(
                    &f.actor(RecoveryPermission::KnowledgeRead)?,
                    &handle,
                    &f.f.authority.mutation_fence(),
                    now_ms()?,
                )?;
        let seal = record.seal.ok_or("published artifact seal")?;
        assert_eq!(f.broker.read_private(&seal)?, bytes);
        let scope =
            chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(&f.profile.scope)?);
        let key = format!(
            "knowledge-checkpoint:v2:revision:{scope}:{}:{id}:1",
            id.len()
        );
        Ok(RetainedCheckpoint {
            checkpoint,
            seal,
            key,
        })
    }
}

pub(super) struct RetirementWriteFault {
    store: Option<SqliteAdmissionOperationStore>,
}

impl RetirementWriteFault {
    pub(super) fn install(f: &KnowledgeFixture) -> TestResult<Self> {
        let store = f.f.authority.admission_operation_store();
        store.inject_checkpoint_retirement_owner_failure_for_test()?;
        Ok(Self { store: Some(store) })
    }

    pub(super) fn clear(mut self) -> TestResult {
        if let Some(store) = self.store.take() {
            store.clear_checkpoint_retirement_owner_failure_for_test()?;
        }
        Ok(())
    }
}

impl Drop for RetirementWriteFault {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let _ = store.clear_checkpoint_retirement_owner_failure_for_test();
        }
    }
}
