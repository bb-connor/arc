//! Revision allocation retains every consumed checkpoint identity.
use super::*;
use std::ops::Deref;

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointHead {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    checkpoint: CheckpointId,
    current_revision: SafeInteger,
    highest_revision: SafeInteger,
    current_envelope: CanonicalPayloadDigest,
}

/// Only this module can mint an allocation from the owning physical writer.
/// No deserialized payload or caller supplies a consumed-revision watermark.
pub(super) struct RevisionAllocation<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    scope: RecoveryScopeV1,
    checkpoint: CheckpointId,
    expected_visible_revision: u64,
    previous_head: Option<protected::ProtectedSourceReference>,
    next_revision: SafeInteger,
}

impl<'tx, 'conn> RevisionAllocation<'tx, 'conn> {
    pub(super) fn next_revision(&self) -> SafeInteger {
        self.next_revision
    }

    pub(super) fn expected_head(&self) -> Option<&protected::ProtectedSourceReference> {
        self.previous_head.as_ref()
    }

    pub(super) fn verify(
        &self,
        transaction: &Transaction<'conn>,
        successor: &LabeledCheckpointV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction))
            || successor.scope != self.scope
            || successor.checkpoint != self.checkpoint
            || successor.revision != self.next_revision
            || successor.revision.get() <= self.expected_visible_revision
        {
            return Err(refused("checkpoint allocation changed its native writer"));
        }
        let head_key = key(&self.scope, &self.checkpoint)?;
        match &self.previous_head {
            Some(expected) => {
                if expected.record_key() != head_key {
                    return Err(refused("checkpoint allocation changed its head"));
                }
                protected::verify_source_reference(transaction, expected)?;
            }
            None => {
                if protected::raw_checked(transaction, &head_key)?.is_some() {
                    return Err(refused("checkpoint allocation appeared during intake"));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn key(
    scope: &RecoveryScopeV1,
    checkpoint: &CheckpointId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-checkpoint-head:{}:{}",
        scope_key(scope)?,
        sha256_hex(&protected::encode(checkpoint)?)
    ))
}

pub(super) fn completed_head(
    checkpoint: &LabeledCheckpointV1,
) -> Result<CheckpointHead, AdmissionOperationStoreError> {
    checkpoint.validate().map_err(refused)?;
    Ok(CheckpointHead {
        domain_version: VersionV1,
        scope: checkpoint.scope.clone(),
        checkpoint: checkpoint.checkpoint.clone(),
        current_revision: checkpoint.revision,
        highest_revision: checkpoint.revision,
        current_envelope: envelope_digest(checkpoint)?,
    })
}

pub(super) fn allocate<'tx, 'conn>(
    transaction: &'tx Transaction<'conn>,
    scope: &RecoveryScopeV1,
    checkpoint: &CheckpointId,
    expected_visible_revision: u64,
    current: Option<&LabeledCheckpointV1>,
) -> Result<RevisionAllocation<'tx, 'conn>, AdmissionOperationStoreError> {
    let visible = current.map_or(0, |value| value.revision.get());
    if visible != expected_visible_revision
        || current.is_some_and(|value| value.scope != *scope || value.checkpoint != *checkpoint)
    {
        return Err(refused("checkpoint visible revision changed"));
    }
    let head_key = key(scope, checkpoint)?;
    let (highest, previous_head) = match protected::raw_checked(transaction, &head_key)? {
        Some(row) => {
            let head: CheckpointHead = protected::decode(&row.payload)?;
            let current = current.ok_or_else(|| refused("checkpoint current identity vanished"))?;
            if row.kind != "command"
                || row.scope != scope_key(scope)?
                || head.scope != *scope
                || head.checkpoint != *checkpoint
                || head.current_revision.get() == 0
                || head.highest_revision < head.current_revision
                || head.current_revision != current.revision
                || head.current_envelope != envelope_digest(current)?
            {
                return Err(refused("checkpoint head identity changed"));
            }
            (
                head.highest_revision.get(),
                Some(protected::source_reference(transaction, &head_key)?),
            )
        }
        None => (
            highest_retained_revision(transaction, scope, checkpoint, visible)?,
            None,
        ),
    };
    let next_revision = SafeInteger::new(
        highest
            .checked_add(1)
            .ok_or_else(|| refused("checkpoint revision exhausted"))?,
    )
    .map_err(refused)?;
    Ok(RevisionAllocation {
        transaction,
        scope: scope.clone(),
        checkpoint: checkpoint.clone(),
        expected_visible_revision,
        previous_head,
        next_revision,
    })
}

fn envelope_digest(
    checkpoint: &LabeledCheckpointV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        *chio_core::sha256(&protected::encode(checkpoint)?).as_bytes(),
    ))
}

fn highest_retained_revision(
    connection: &Connection,
    scope: &RecoveryScopeV1,
    checkpoint: &CheckpointId,
    visible: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let mut highest = visible;
    let legacy = head::legacy_checkpoint_key(scope, checkpoint, 0)?;
    let modern = head::checkpoint_revision_key(scope, checkpoint, 1)?;
    let modern = modern
        .strip_suffix(":1")
        .ok_or_else(|| refused("checkpoint revision prefix"))?;
    for base in [legacy.as_str(), modern] {
        let prefix = format!("{base}:");
        let upper = format!("{base};");
        let mut statement = connection
            .prepare(
                "SELECT record_key FROM (
                     SELECT record_key FROM admission_operation_recovery_records
                     WHERE record_key >= ?1 AND record_key < ?2
                     UNION
                     SELECT record_key FROM admission_operation_recovery_events
                     WHERE record_key >= ?1 AND record_key < ?2
                     UNION
                     SELECT projection_key AS record_key FROM authority_global_commits
                     WHERE projection_kind='recovery'
                       AND projection_key >= ?1 AND projection_key < ?2
                 ) WHERE length(record_key) > length(?1)
                     AND substr(record_key,length(?1)+1) NOT GLOB '*[^0-9]*'
                   ORDER BY record_key",
            )
            .map_err(sqlite_error)?;
        let mut keys = statement.query([&prefix, &upper]).map_err(sqlite_error)?;
        while let Some(row) = keys.next().map_err(sqlite_error)? {
            let record_key: String = row.get(0).map_err(sqlite_error)?;
            let retained =
                super::reference_source::checkpoint_reference_source(connection, &record_key)?
                    .ok_or_else(|| refused("checkpoint retained source disappeared"))?;
            if retained.scope() != scope {
                return Err(refused("checkpoint retained source scope"));
            }
            // Foreign numeric child identifiers keep their own custody.
            if retained.checkpoint() == checkpoint {
                highest = highest.max(retained.revision());
            }
        }
    }
    Ok(highest)
}
