//! The native checkpoint factory owns the exact highwater transition.
use super::*;
use crate::admission_operation_store::knowledge::VerifiedCheckpointHeadWrite;
use std::ops::Deref;

const MAX_HEAD_BYTES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointHead {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    checkpoint: CheckpointId,
    current_revision: SafeInteger,
    highest_revision: SafeInteger,
    current_envelope: CanonicalPayloadDigest,
}

/// Consuming the affine native proof permits one exact reversible head write.
/// Failure propagates to the outer immutable/latest/head transaction. There is
/// no finishing loan or independent caller-selected protected record here.
pub(in crate::admission_operation_store) fn persist_checkpoint_head<'tx, 'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedCheckpointHeadWrite<'tx, 'conn>,
) -> Result<(ProtectedSourceReference, ProtectedMutationDelta), AdmissionOperationStoreError> {
    require_checkpoint_head_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if !std::ptr::eq::<Connection>(Deref::deref(proof.transaction()), Deref::deref(tx))
        || proof.scope().authority_domain.as_str() != owner.fence.store_uuid
        || proof.canonical_payload().len() > MAX_HEAD_BYTES
    {
        return Err(invariant("checkpoint head changed its owning writer"));
    }
    proof.verify(tx)?;
    let head: CheckpointHead = decode(proof.canonical_payload())?;
    let scope = scope_key(proof.scope())?;
    let key = format!(
        "knowledge-checkpoint-head:{scope}:{}",
        sha256_hex(&encode(&head.checkpoint)?)
    );
    if head.scope != *proof.scope()
        || head.current_revision.get() == 0
        || head.highest_revision != head.current_revision
        || key != proof.key()
    {
        return Err(invariant("checkpoint head lost its exact native identity"));
    }
    for source in [proof.current_envelope_source(), proof.revision_source()] {
        verify_source_reference(tx, source)?;
        let row = raw_checked(tx, source.record_key())?
            .ok_or_else(|| invariant("checkpoint successor source disappeared"))?;
        if source.kind() != "command"
            || source.scope_key() != scope
            || row.kind != "command"
            || row.scope != scope
            || head.current_envelope
                != CanonicalPayloadDigest::from_bytes(*chio_core::sha256(&row.payload).as_bytes())
        {
            return Err(invariant("checkpoint head changed its successor envelope"));
        }
        require_ordinary_header(tx, source.record_key())?;
    }
    let previous = raw_checked(tx, &key)?;
    let next_version = match (proof.expected_head(), previous) {
        (Some(expected), Some(row)) => {
            verify_source_reference(tx, expected)?;
            require_ordinary_header(tx, &key)?;
            let prior: CheckpointHead = decode(&row.payload)?;
            if expected.record_key() != key
                || expected.kind() != "command"
                || expected.scope_key() != scope
                || row.kind != "command"
                || row.scope != scope
                || row.version != expected.version()
                || row.payload.len() > MAX_HEAD_BYTES
                || prior.scope != head.scope
                || prior.checkpoint != head.checkpoint
                || prior.current_revision.get() == 0
                || prior.highest_revision < prior.current_revision
                || head.current_revision <= prior.highest_revision
            {
                return Err(invariant("checkpoint head lost its current CAS"));
            }
            row.version
                .checked_add(1)
                .ok_or_else(|| invariant("checkpoint head version exhausted"))?
        }
        (None, None) => 1,
        _ => return Err(invariant("checkpoint head changed during native intake")),
    };
    SafeInteger::new(next_version).map_err(|_| invariant("checkpoint head version exhausted"))?;
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    persist_record(
        tx,
        owner,
        &key,
        &scope,
        "command",
        proof.canonical_payload(),
        None,
    )?;
    let source = source_reference(tx, &key)?;
    if source.version() != next_version || source.scope_key() != scope || source.kind() != "command"
    {
        return Err(invariant("checkpoint head writer changed its exact frame"));
    }
    Ok((
        source,
        ProtectedMutationDelta {
            mutations: 1,
            encoded_bytes: proof.canonical_payload().len() as u64,
        },
    ))
}

fn require_checkpoint_head_format(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let version: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION < 40
        || version != Some(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    {
        return Err(invariant(
            "checkpoint heads require the current serving format",
        ));
    }
    Ok(())
}

fn require_ordinary_header(tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
    let ordinary: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !ordinary {
        return Err(invariant(
            "checkpoint head metadata acquired a native request",
        ));
    }
    Ok(())
}
