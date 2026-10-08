use super::*;

mod head;
mod head_write;
mod watermark;
pub(in crate::admission_operation_store) use head_write::VerifiedCheckpointHeadWrite;
#[cfg(feature = "admission-test-support")]
mod history_trace;
mod reference_source;
mod restore;
#[cfg(feature = "admission-test-support")]
mod restore_test_support;
mod retirement;
use head::{checkpoint_key, load_checkpoint, load_visible_checkpoint, retain_checkpoint_revision};
#[cfg(all(test, unix))]
use head::{checkpoint_revision_key, legacy_checkpoint_key};
pub(super) use reference_source::{checkpoint_reference_source, CheckpointReferenceSource};
pub(in crate::admission_operation_store) use restore::AuthenticatedCheckpointRestoreEncodingSource;
pub use restore::NativeCheckpointRestore;
pub(super) use restore::{restore_reference_source, RestoreReferenceSource};
#[cfg(feature = "admission-test-support")]
pub use restore_test_support::{
    construct_legacy_checkpoint_restore_fixture, LegacyCheckpointRestoreFixtureScope,
};
#[cfg(all(test, unix))]
mod tests;

pub(super) fn pins(
    tx: &Connection,
    key: &str,
    reference: &ArtifactVersionRefV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("checkpoint pin absent"))?;
    let checkpoint: LabeledCheckpointV1 = protected::decode(&row.payload)?;
    if row.kind != "command" || row.scope != scope_key(&checkpoint.scope)? {
        return Err(refused("checkpoint pin source ownership"));
    }
    head::validate_record_key(&checkpoint, key)?;
    if retirement::revision_is_retired(tx, &checkpoint)? {
        return Ok(false);
    }
    Ok(checkpoint.artifacts.as_slice().contains(reference)
        || checkpoint
            .model_contexts
            .as_slice()
            .iter()
            .any(|model| model.side_files.as_slice().contains(reference)))
}

pub(super) fn restore_pins(
    tx: &Connection,
    key: &str,
    reference: &ArtifactVersionRefV1,
) -> Result<bool, AdmissionOperationStoreError> {
    restore::pins(tx, key, reference)
}

impl SqliteAdmissionOperationStore {
    pub fn save_labeled_checkpoint(
        &self,
        actor: &AuthenticatedRecoveryActor,
        update: NativeCheckpointUpdate<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<LabeledCheckpointV1, AdmissionOperationStoreError> {
        let NativeCheckpointUpdate {
            checkpoint: id,
            expected_revision: expected,
            artifacts,
            model_contexts: models,
        } = update;
        if actor.permission() != RecoveryPermission::KnowledgeWrite {
            return Err(refused("checkpoint authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, trusted_now| {
            let key = checkpoint_key(actor.scope(), id)?;
            let old = load_checkpoint(&tx, actor.scope(), id, 0)?;
            if old.as_ref().map_or(0, |old| old.revision.get()) != expected {
                return Err(refused("checkpoint CAS"));
            }
            let allocation = watermark::allocate(&tx, actor.scope(), id, expected, old.as_ref())?;
            let roots = NonEmptyBoundedList::new(artifacts.to_vec()).map_err(refused)?;
            let models = BoundedList::new(models.to_vec()).map_err(refused)?;
            for context in models.as_slice() {
                if !profile.recipients.as_slice().iter().any(|selection| {
                    selection.recipient.sink
                        == (ArtifactSinkV1::Model {
                            context: context.clone(),
                        })
                }) {
                    return Err(refused("unselected model context"));
                }
            }
            let mut deps = artifacts.to_vec();
            for model in models.as_slice() {
                deps.extend_from_slice(model.side_files.as_slice());
            }
            let records = traversal::dependencies(&tx, actor.scope(), &deps)?;
            let label = traversal::join_metadata(
                source(&tx, &profile.native_authority, &profile.producer_context)?,
                &records,
            )?;
            let native_evidence: i64 = tx
                .query_row(
                    "SELECT COALESCE(max(commit_sequence),0) FROM authority_global_commits",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let checkpoint = LabeledCheckpointV1 {
                domain_version: VersionV1,
                checkpoint: id.clone(),
                revision: allocation.next_revision(),
                scope: actor.scope().clone(),
                runtime: ProtectedText::new(profile.producer_context.as_v1().session_id().as_str())
                    .map_err(refused)?,
                artifacts: roots,
                model_contexts: models,
                label,
                influence: traversal::influence(
                    &tx,
                    &profile.native_authority,
                    &profile.producer_context,
                    &records,
                    false,
                )?,
                lineage: IsolationLineageId::new(
                    profile.producer_context.as_v1().lineage_root_id().as_str(),
                )
                .map_err(refused)?,
                isolation_epoch: ProtectedText::new(
                    profile
                        .producer_context
                        .as_v1()
                        .isolation_epoch_id()
                        .as_str(),
                )
                .map_err(refused)?,
                native_evidence_sequence: SafeInteger::new(
                    u64::try_from(native_evidence).map_err(refused)?,
                )
                .map_err(refused)?,
                policy: profile.policy,
            };
            checkpoint.validate().map_err(refused)?;
            if protected::encode(&checkpoint)?.len() > MAX_CHECKPOINT_ENVELOPE_BYTES {
                return Err(refused("checkpoint envelope bound"));
            }
            traversal::ensure_audience(&tx, actor, &checkpoint.label)?;
            // Revisions remain individually pinned and restorable. GC cannot
            // discard references required by an older retained checkpoint. On
            // upgrade, preserve the previous valid legacy current envelope.
            if let Some(old) = &old {
                retain_checkpoint_revision(&tx, &self.serving_owner, old)?;
                if !retirement::revision_is_retired(&tx, old)? {
                    super::reference_custody::retain_checkpoint_references(
                        &tx,
                        &self.serving_owner,
                        &head::checkpoint_revision_key(
                            &old.scope,
                            &old.checkpoint,
                            old.revision.get(),
                        )?,
                    )?;
                }
            }
            retain_checkpoint_revision(&tx, &self.serving_owner, &checkpoint)?;
            super::reference_custody::retain_checkpoint_references(
                &tx,
                &self.serving_owner,
                &head::checkpoint_revision_key(actor.scope(), id, checkpoint.revision.get())?,
            )?;
            save(&tx, &self.serving_owner, actor.scope(), &key, &checkpoint)?;
            let head = VerifiedCheckpointHeadWrite::new(
                &tx,
                actor,
                profile,
                trusted_now,
                allocation,
                &checkpoint,
            )?;
            let (_head_source, _head_delta) =
                protected::persist_checkpoint_head(&tx, &self.serving_owner, head)?;
            Ok((tx, checkpoint))
        })
    }
    /// Returns only a current audience-checked labeled envelope, never bytes.
    pub fn read_labeled_checkpoint(
        &self,
        actor: &AuthenticatedRecoveryActor,
        id: &CheckpointId,
        revision: u64,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<LabeledCheckpointV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("checkpoint read authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let checkpoint = load_visible_checkpoint(&tx, actor.scope(), id, revision)?
                .ok_or_else(|| refused("checkpoint absent"))?;
            if checkpoint.scope != *actor.scope()
                || checkpoint.runtime.as_str()
                    != profile.producer_context.as_v1().session_id().as_str()
                || checkpoint.lineage.as_str()
                    != profile.producer_context.as_v1().lineage_root_id().as_str()
                || checkpoint.isolation_epoch.as_str()
                    != profile
                        .producer_context
                        .as_v1()
                        .isolation_epoch_id()
                        .as_str()
                || checkpoint.policy != profile.policy
            {
                return Err(refused("checkpoint identity"));
            }
            traversal::ensure_audience(&tx, actor, &checkpoint.label)?;
            for context in checkpoint.model_contexts.as_slice() {
                if !profile.recipients.as_slice().iter().any(|entry| {
                    entry.recipient.sink
                        == (ArtifactSinkV1::Model {
                            context: context.clone(),
                        })
                }) {
                    return Err(refused("provider context changed"));
                }
            }
            traversal::dependencies(&tx, actor.scope(), checkpoint.artifacts.as_slice())?;
            Ok((tx, checkpoint))
        })
    }
}
