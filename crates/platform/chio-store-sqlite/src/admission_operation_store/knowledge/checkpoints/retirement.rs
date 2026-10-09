//! Exact revision authority retirement retains its immutable checkpoint.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRevisionRetirement {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    checkpoint: CheckpointId,
    revision: SafeInteger,
    envelope: CanonicalPayloadDigest,
    principal: chio_security_types::PrincipalId,
    authority_scope: AuthorityScopeDigest,
    retired_at: SafeInteger,
}

fn retirement_key(
    scope: &RecoveryScopeV1,
    checkpoint: &CheckpointId,
    revision: u64,
) -> Result<String, AdmissionOperationStoreError> {
    if revision == 0 {
        return Err(refused("checkpoint retirement revision"));
    }
    SafeInteger::new(revision).map_err(refused)?;
    Ok(format!(
        "knowledge-checkpoint-retired:{}:{}:{revision}",
        scope_key(scope)?,
        sha256_hex(&protected::encode(checkpoint)?)
    ))
}

fn envelope_digest(
    checkpoint: &LabeledCheckpointV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        *chio_core::sha256(&protected::encode(checkpoint)?).as_bytes(),
    ))
}

pub(super) fn revision_is_retired(
    tx: &Connection,
    checkpoint: &LabeledCheckpointV1,
) -> Result<bool, AdmissionOperationStoreError> {
    retirement_source(tx, checkpoint).map(|source| source.is_some())
}

pub(super) fn retirement_source(
    tx: &Connection,
    checkpoint: &LabeledCheckpointV1,
) -> Result<Option<protected::ProtectedSourceReference>, AdmissionOperationStoreError> {
    let key = retirement_key(
        &checkpoint.scope,
        &checkpoint.checkpoint,
        checkpoint.revision.get(),
    )?;
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let retired: CheckpointRevisionRetirement = protected::decode(&row.payload)?;
    if row.version != 1
        || row.kind != "command"
        || row.scope != scope_key(&checkpoint.scope)?
        || retired.scope != checkpoint.scope
        || retired.checkpoint != checkpoint.checkpoint
        || retired.revision != checkpoint.revision
        || retired.envelope != envelope_digest(checkpoint)?
    {
        return Err(refused("checkpoint retired identity changed"));
    }
    protected::source_reference(tx, &key).map(Some)
}

impl SqliteAdmissionOperationStore {
    /// Carry an authentic retained revision into current logical custody under
    /// fresh storage administration. This allocates no new checkpoint revision
    /// and supplies no restore, execution or byte-delivery authority.
    pub fn migrate_checkpoint_reference_custody(
        &self,
        actor: &AuthenticatedRecoveryActor,
        id: &CheckpointId,
        revision: u64,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin || revision == 0 {
            return Err(refused("checkpoint custody migration authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, _, _| {
            let latest = load_checkpoint(&tx, actor.scope(), id, 0)?;
            let checkpoint =
                if let Some(latest) = latest.filter(|latest| latest.revision.get() == revision) {
                    latest
                } else {
                    load_checkpoint(&tx, actor.scope(), id, revision)?
                        .ok_or_else(|| refused("checkpoint custody migration absent"))?
                };
            traversal::ensure_audience(&tx, actor, &checkpoint.label)?;
            retain_checkpoint_revision(&tx, &self.serving_owner, &checkpoint)?;
            if !revision_is_retired(&tx, &checkpoint)? {
                super::super::reference_custody::retain_checkpoint_references(
                    &tx,
                    &self.serving_owner,
                    &head::checkpoint_revision_key(actor.scope(), id, revision)?,
                )?;
            }
            Ok((tx, ()))
        })
    }

    /// One-way retirement of exact checkpoint restore authority. The retained
    /// envelope remains evidence and never becomes a new revision reservation.
    pub fn retire_checkpoint_revision(
        &self,
        actor: &AuthenticatedRecoveryActor,
        id: &CheckpointId,
        revision: u64,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin || revision == 0 {
            return Err(refused("checkpoint retirement authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, _, now| {
            let latest = head::load_checkpoint_with_key(&tx, actor.scope(), id, 0)?;
            let (checkpoint, source_key) = if let Some(latest) =
                latest.filter(|(latest, _)| latest.revision.get() == revision)
            {
                latest
            } else {
                // This administrative ownership change grants no read.
                // Authentic pre-reset history above visible latest can be
                // retired without making that history restorable.
                head::load_checkpoint_with_key(&tx, actor.scope(), id, revision)?
                    .ok_or_else(|| refused("checkpoint retirement absent"))?
            };
            traversal::ensure_audience(&tx, actor, &checkpoint.label)?;
            if revision_is_retired(&tx, &checkpoint)? {
                return Ok((tx, ()));
            }
            let source = checkpoint_reference_source(&tx, &source_key)?
                .ok_or_else(|| refused("checkpoint retirement source absent"))?;
            if source.canonical_envelope()? != protected::encode(&checkpoint)? {
                return Err(refused("checkpoint retirement selected envelope changed"));
            }
            let key = retirement_key(actor.scope(), id, revision)?;
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &key,
                &CheckpointRevisionRetirement {
                    domain_version: VersionV1,
                    scope: actor.scope().clone(),
                    checkpoint: id.clone(),
                    revision: checkpoint.revision,
                    envelope: envelope_digest(&checkpoint)?,
                    principal: actor.principal().clone(),
                    authority_scope: protected::deployment_tx(&tx, actor.scope())?.authority_scope,
                    retired_at: SafeInteger::new(now).map_err(refused)?,
                },
            )?;
            protected::verify_source_reference(&tx, source.source())?;
            super::super::reference_retirement::retire_checkpoint_references(
                &tx,
                &self.serving_owner,
                source.source().record_key(),
            )?;
            Ok((tx, ()))
        })
    }
}
