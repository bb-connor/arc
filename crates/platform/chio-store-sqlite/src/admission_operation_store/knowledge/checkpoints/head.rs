//! Authenticated checkpoint history with framed, disjoint key domains.
use super::*;

pub(super) fn checkpoint_key(
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
) -> Result<String, AdmissionOperationStoreError> {
    // Latest and history have distinct domains. Each opaque identifier is
    // byte-length framed, so a numeric suffix cannot alias another revision.
    Ok(format!(
        "knowledge-checkpoint:v2:latest:{}:{}:{}",
        scope_key(scope)?,
        id.as_str().len(),
        id.as_str()
    ))
}

pub(super) fn checkpoint_revision_key(
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
    revision: u64,
) -> Result<String, AdmissionOperationStoreError> {
    if revision == 0 {
        return Err(refused("checkpoint revision key"));
    }
    Ok(format!(
        "knowledge-checkpoint:v2:revision:{}:{}:{}:{revision}",
        scope_key(scope)?,
        id.as_str().len(),
        id.as_str()
    ))
}

fn validate_checkpoint_identity(
    checkpoint: &LabeledCheckpointV1,
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
    revision: u64,
) -> Result<(), AdmissionOperationStoreError> {
    checkpoint.validate().map_err(refused)?;
    if checkpoint.scope != *scope
        || checkpoint.checkpoint != *id
        || (revision != 0 && checkpoint.revision.get() != revision)
    {
        return Err(refused("checkpoint key identity"));
    }
    Ok(())
}

pub(super) fn validate_record_key(
    checkpoint: &LabeledCheckpointV1,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    checkpoint.validate().map_err(refused)?;
    let scope = &checkpoint.scope;
    let id = &checkpoint.checkpoint;
    let revision = checkpoint.revision.get();
    if key != checkpoint_key(scope, id)? && key != checkpoint_revision_key(scope, id, revision)? {
        return Err(refused("checkpoint physical record identity"));
    }
    Ok(())
}

pub(super) fn load_checkpoint(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
    revision: u64,
) -> Result<Option<LabeledCheckpointV1>, AdmissionOperationStoreError> {
    Ok(load_checkpoint_with_key(tx, scope, id, revision)?.map(|(checkpoint, _)| checkpoint))
}

/// Keep the physical source paired with the authenticated envelope selected by
/// identity-safe resolution. A later mutation must not reselect it by presence.
pub(super) fn load_checkpoint_with_key(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
    revision: u64,
) -> Result<Option<(LabeledCheckpointV1, String)>, AdmissionOperationStoreError> {
    let key = if revision == 0 {
        checkpoint_key(scope, id)?
    } else {
        checkpoint_revision_key(scope, id, revision)?
    };
    if let Some(checkpoint) = load::<LabeledCheckpointV1>(tx, &key)? {
        validate_checkpoint_identity(&checkpoint, scope, id, revision)?;
        return Ok(Some((checkpoint, key)));
    }

    Ok(None)
}

/// Public revision reads are fenced by the validated current envelope.
pub(super) fn load_visible_checkpoint(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
    revision: u64,
) -> Result<Option<LabeledCheckpointV1>, AdmissionOperationStoreError> {
    let Some(latest) = load_checkpoint(tx, scope, id, 0)? else {
        return Ok(None);
    };
    if revision > latest.revision.get() {
        return Err(refused("checkpoint revision exceeds current latest"));
    }
    let selected = if revision == 0 || revision == latest.revision.get() {
        Some(latest)
    } else {
        load_checkpoint(tx, scope, id, revision)?
    };
    if selected
        .as_ref()
        .map(|checkpoint| super::retirement::revision_is_retired(tx, checkpoint))
        .transpose()?
        .unwrap_or(false)
    {
        return Err(refused("checkpoint revision authority retired"));
    }
    Ok(selected)
}

/// Retain one immutable revision through the typed intake. Its reference
/// owner is charged separately by the existing checkpoint custody writer.
pub(super) fn retain_checkpoint_revision(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
    checkpoint: &LabeledCheckpointV1,
) -> Result<(), AdmissionOperationStoreError> {
    if let Some(intake) =
        super::super::intake::AuthenticatedKnowledgeIntakeSource::checkpoint_revision(
            tx, actor, profile, now, checkpoint,
        )?
    {
        protected::persist_knowledge_intake(tx, owner, intake)?;
    }
    Ok(())
}

/// The new immutable revision row, or none when the revision is retired or
/// already retained exactly. A retained different envelope refuses; an
/// existing revision is never upserted.
pub(in crate::admission_operation_store::knowledge) fn derive_revision(
    tx: &Connection,
    checkpoint: &LabeledCheckpointV1,
) -> Result<Option<DerivedWrite>, AdmissionOperationStoreError> {
    let revision = checkpoint.revision.get();
    validate_checkpoint_identity(
        checkpoint,
        &checkpoint.scope,
        &checkpoint.checkpoint,
        revision,
    )?;
    // Retirement is one-way. Carrying a historical current envelope into a
    // later CAS must not reacquire its retired reference ownership.
    if super::retirement::revision_is_retired(tx, checkpoint)? {
        return Ok(None);
    }
    let key = checkpoint_revision_key(&checkpoint.scope, &checkpoint.checkpoint, revision)?;
    if let Some(retained) =
        load_checkpoint(tx, &checkpoint.scope, &checkpoint.checkpoint, revision)?
    {
        if retained != *checkpoint {
            #[cfg(feature = "admission-test-support")]
            super::history_trace::immutable_collision();
            return Err(refused("immutable checkpoint revision"));
        }
        return Ok(None);
    }
    Ok(Some(DerivedWrite {
        scope_key: scope_key(&checkpoint.scope)?,
        payload: protected::encode(checkpoint)?,
        key,
        expected: None,
    }))
}

/// The current envelope advanced to its newer retained revision, CAS-bound
/// to the exact current head, with the retained revision head it names. The
/// exact current envelope derives no write.
pub(in crate::admission_operation_store::knowledge) fn derive_current(
    tx: &Connection,
    checkpoint: &LabeledCheckpointV1,
) -> Result<Option<(DerivedWrite, protected::ProtectedSourceReference)>, AdmissionOperationStoreError>
{
    let (scope, id) = (&checkpoint.scope, &checkpoint.checkpoint);
    validate_checkpoint_identity(checkpoint, scope, id, 0)?;
    let revision = checkpoint.revision.get();
    if load_checkpoint(tx, scope, id, revision)?.as_ref() != Some(checkpoint) {
        return Err(refused("checkpoint current names no retained revision"));
    }
    let key = checkpoint_key(scope, id)?;
    let expected = match load_checkpoint(tx, scope, id, 0)? {
        Some(current) if current == *checkpoint => return Ok(None),
        Some(current) if current.revision.get() >= revision => {
            return Err(refused("checkpoint CAS"));
        }
        Some(_) => Some(protected::source_reference(tx, &key)?),
        None => None,
    };
    Ok(Some((
        DerivedWrite {
            scope_key: scope_key(scope)?,
            payload: protected::encode(checkpoint)?,
            key,
            expected,
        },
        protected::source_reference(tx, &checkpoint_revision_key(scope, id, revision)?)?,
    )))
}
