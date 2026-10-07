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
            let latest = load_checkpoint(&tx, actor.scope(), id, 0)?;
            let checkpoint =
                if let Some(latest) = latest.filter(|latest| latest.revision.get() == revision) {
                    latest
                } else {
                    // This administrative ownership change grants no read.
                    // Authentic pre-reset history above visible latest can be
                    // retired without making that history restorable.
                    load_checkpoint(&tx, actor.scope(), id, revision)?
                        .ok_or_else(|| refused("checkpoint retirement absent"))?
                };
            traversal::ensure_audience(&tx, actor, &checkpoint.label)?;
            if revision_is_retired(&tx, &checkpoint)? {
                return Ok((tx, ()));
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
            Ok((tx, ()))
        })
    }
}
