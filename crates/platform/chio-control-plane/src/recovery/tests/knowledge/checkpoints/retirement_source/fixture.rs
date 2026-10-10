//! Original cold sources and connection-local fail-only controls.
use super::*;

pub(super) struct LegacyCheckpoint {
    pub(super) checkpoint: LabeledCheckpointV1,
    pub(super) seal: ArtifactBlobSealV1,
    pub(super) key: String,
}

impl LegacyCheckpoint {
    pub(super) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.checkpoint.artifacts.as_slice()[0]
    }
}

pub(super) struct ColdRetirementFixture {
    pub(super) knowledge: KnowledgeFixture,
    pub(super) own: LegacyCheckpoint,
    pub(super) foreign: LegacyCheckpoint,
}

impl ColdRetirementFixture {
    pub(super) fn new() -> TestResult<Self> {
        let mut originals = None;
        let knowledge = KnowledgeFixture::from_before_activation(
            RecoveryFixture::new(false)?,
            |f, profile, broker| {
                let connection = rusqlite::Connection::open(f.path.join("admission.db"))?;
                let ready: i64 = connection.query_row(
                    "SELECT count(*) FROM admission_operation_recovery_records
                     WHERE record_key GLOB 'knowledge-*'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(ready, 0, "legacy sources must precede the first activation");
                // Model the retained ordinary predecessor format in its original
                // authority. The real broker owns the bytes, the protected fixture
                // writer owns the events, and configure_knowledge alone creates
                // every cold owner, capacity account and Ready marker.
                let own_seal = broker.stage(
                    &ArtifactObjectId::new("job")?,
                    &profile.scope.process_id,
                    b"own-legacy",
                )?;
                let foreign_seal = broker.stage(
                    &ArtifactObjectId::new("job:1")?,
                    &profile.scope.process_id,
                    b"foreign-legacy",
                )?;
                assert_eq!(broker.read_private(&own_seal)?, b"own-legacy");
                assert_eq!(broker.read_private(&foreign_seal)?, b"foreign-legacy");
                let inputs = [
                    (CheckpointId::new("job")?, own_seal.clone()),
                    (CheckpointId::new("job:1")?, foreign_seal.clone()),
                ];
                let actor = f.kernel.authenticate_recovery_actor(
                    &profile.scope,
                    &f.control,
                    RecoveryPermission::KnowledgeWrite,
                )?;
                let store = f.authority.admission_operation_store();
                let mut retained = store
                    .retain_cold_legacy_checkpoint_fixture(
                        &actor,
                        profile,
                        &inputs,
                        &f.authority.mutation_fence(),
                        now_ms()?,
                    )?
                    .into_iter();
                let scope = chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(
                    &profile.scope,
                )?);
                let own = LegacyCheckpoint {
                    checkpoint: retained.next().ok_or("own legacy checkpoint")?,
                    seal: own_seal,
                    key: format!("knowledge-checkpoint:{scope}:job"),
                };
                let foreign = LegacyCheckpoint {
                    checkpoint: retained.next().ok_or("foreign legacy checkpoint")?,
                    seal: foreign_seal,
                    key: format!("knowledge-checkpoint:{scope}:job:1"),
                };
                assert!(retained.next().is_none());
                assert!(
                    store
                        .retain_cold_legacy_checkpoint_fixture(
                            &actor,
                            profile,
                            &inputs,
                            &f.authority.mutation_fence(),
                            now_ms()?,
                        )
                        .is_err(),
                    "a nonempty original scope cannot be reseeded"
                );
                assert_eq!(format!("{}:1", own.key), foreign.key);
                let indices: i64 = connection.query_row(
                    "SELECT count(*) FROM admission_operation_recovery_records
                     WHERE record_key GLOB 'knowledge-reference-*'
                        OR record_key GLOB 'knowledge-checkpoint:v2:*'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(
                    indices, 0,
                    "fixture must not manufacture protected ownership"
                );
                originals = Some((own, foreign));
                Ok(())
            },
        )?;
        let (own, foreign) = originals.ok_or("original cold checkpoint sources")?;
        let before = retained_state(&knowledge)?;
        assert!(
            knowledge
                .f
                .authority
                .admission_operation_store()
                .retain_cold_legacy_checkpoint_fixture(
                    &knowledge.actor(RecoveryPermission::KnowledgeWrite)?,
                    &knowledge.profile,
                    &[(own.checkpoint.checkpoint.clone(), own.seal.clone())],
                    &knowledge.f.authority.mutation_fence(),
                    now_ms()?,
                )
                .is_err(),
            "the cold fixture cannot reset an activated scope"
        );
        assert_eq!(retained_state(&knowledge)?, before);
        Ok(Self {
            knowledge,
            own,
            foreign,
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
