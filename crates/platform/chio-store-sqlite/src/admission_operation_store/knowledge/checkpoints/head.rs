//! Authenticated checkpoint history and identity-safe legacy resolution.
use super::*;

pub(super) fn checkpoint_key(
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
) -> Result<String, AdmissionOperationStoreError> {
    // The format domain precedes the fixed scope digest, so these keys cannot
    // alias legacy keys. Latest and history have distinct domains, and each
    // opaque identifier is byte-length framed inside its domain.
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

pub(super) fn legacy_checkpoint_key(
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
    revision: u64,
) -> Result<String, AdmissionOperationStoreError> {
    let key = format!("knowledge-checkpoint:{}:{}", scope_key(scope)?, id.as_str());
    Ok(if revision == 0 {
        key
    } else {
        format!("{key}:{revision}")
    })
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
    if key != checkpoint_key(scope, id)?
        && key != checkpoint_revision_key(scope, id, revision)?
        && key != legacy_checkpoint_key(scope, id, 0)?
        && key != legacy_checkpoint_key(scope, id, revision)?
    {
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

    let legacy_key = legacy_checkpoint_key(scope, id, revision)?;
    let Some(checkpoint) = load::<LabeledCheckpointV1>(tx, &legacy_key)? else {
        return if revision == 0 {
            highest_legacy_checkpoint(tx, scope, id)
        } else {
            Ok(None)
        };
    };
    checkpoint.validate().map_err(refused)?;
    if checkpoint.scope != *scope
        || (legacy_key != legacy_checkpoint_key(scope, &checkpoint.checkpoint, 0)?
            && legacy_key
                != legacy_checkpoint_key(scope, &checkpoint.checkpoint, checkpoint.revision.get())?)
    {
        return Err(refused("legacy checkpoint key identity"));
    }
    // A valid legacy slot may be another checkpoint's latest or revision. It
    // supplies neither a CAS revision nor restore authority for this identity.
    // Leaving that slot untouched also preserves its existing artifact pins.
    if checkpoint.checkpoint != *id {
        return if revision == 0 {
            highest_legacy_checkpoint(tx, scope, id)
        } else {
            Ok(None)
        };
    }
    validate_checkpoint_identity(&checkpoint, scope, id, revision)?;
    Ok(Some((checkpoint, legacy_key)))
}

/// Only decimal revision suffixes can belong to this historical identity.
/// Child identifiers can occupy those same legacy slots, so each candidate is
/// authenticated and its full checkpoint identity is checked before adoption.
/// Streaming keeps application memory independent of retained history size.
fn highest_legacy_checkpoint(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &CheckpointId,
) -> Result<Option<(LabeledCheckpointV1, String)>, AdmissionOperationStoreError> {
    let latest = legacy_checkpoint_key(scope, id, 0)?;
    let prefix = format!("{latest}:");
    let upper = format!("{latest};");
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key >= ?1 AND record_key < ?2
               AND length(record_key) > length(?1)
               AND substr(record_key,length(?1)+1) NOT GLOB '*[^0-9]*'
             ORDER BY length(record_key) DESC,record_key DESC",
        )
        .map_err(sqlite_error)?;
    let mut keys = statement.query([&prefix, &upper]).map_err(sqlite_error)?;
    while let Some(row) = keys.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let checkpoint: LabeledCheckpointV1 =
            load(tx, &key)?.ok_or_else(|| refused("legacy checkpoint history"))?;
        checkpoint.validate().map_err(refused)?;
        if checkpoint.scope != *scope
            || (key != legacy_checkpoint_key(scope, &checkpoint.checkpoint, 0)?
                && key
                    != legacy_checkpoint_key(
                        scope,
                        &checkpoint.checkpoint,
                        checkpoint.revision.get(),
                    )?)
        {
            return Err(refused("legacy checkpoint history identity"));
        }
        if checkpoint.checkpoint == *id {
            return Ok(Some((checkpoint, key)));
        }
    }
    Ok(None)
}

/// Public revision reads are fenced by the validated current envelope. The
/// current legacy envelope remains authoritative when its revision slot was
/// overwritten by another checkpoint identity before the format upgrade.
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

pub(super) fn retain_checkpoint_revision(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    checkpoint: &LabeledCheckpointV1,
) -> Result<(), AdmissionOperationStoreError> {
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
        return Ok(());
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
        if protected::raw(tx, &key)?.is_some() {
            return Ok(());
        }
    }
    // The serving authority's IMMEDIATE transaction serializes this insert.
    // Existing retained revisions are compared above and never upserted.
    save(tx, owner, &checkpoint.scope, &key, checkpoint)
}
