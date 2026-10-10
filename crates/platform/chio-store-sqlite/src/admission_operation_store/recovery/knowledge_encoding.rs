//! Native codec owners admit one complete bounded root and immutable chunk set.
use super::*;
use crate::admission_operation_store::knowledge::encoding::chunks::{
    MAX_CHUNK_COUNT, MAX_ENCODED_SET_BYTES,
};
use crate::admission_operation_store::knowledge::encoding::write::VerifiedKnowledgeEncodingWrite;
use std::ops::Deref;

#[cfg(feature = "admission-test-support")]
#[path = "knowledge_encoding/extra_ordinal_fixture.rs"]
mod extra_ordinal_fixture;
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) use extra_ordinal_fixture::retain_restore_extra_ordinal_fixture;

/// This affine source plan is consumed in its original native writer. Every
/// head and absent chunk is checked before the first append. This logical
/// persistence path provides no independent physical finishing credit.
pub(in crate::admission_operation_store) fn persist_knowledge_encoding<'tx, 'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedKnowledgeEncodingWrite<'tx, 'conn>,
) -> Result<(ProtectedSourceReference, ProtectedMutationDelta), AdmissionOperationStoreError> {
    require_encoding_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if !std::ptr::eq::<Connection>(Deref::deref(proof.transaction()), Deref::deref(tx))
        || proof.staged_chunks().len() > MAX_CHUNK_COUNT
        || proof.root_key().is_empty()
        || proof.root_key().len() > 512
        || proof.root_payload().is_empty()
        || proof.root_payload().len() > MAX_RECOVERY_RECORD_BYTES
    {
        return Err(invariant("knowledge encoding changed its bounded writer"));
    }
    proof.verify(tx)?;
    let _: serde_json::Value = decode(proof.root_payload())?;
    let mut bytes = proof.root_payload().len() as u64;
    let mut keys = std::collections::BTreeSet::new();
    keys.insert(proof.root_key());
    for chunk in proof.staged_chunks() {
        if chunk.key().is_empty()
            || chunk.key().len() > 512
            || chunk.scope() != proof.scope_key()
            || chunk.payload().is_empty()
            || chunk.payload().len() > MAX_RECOVERY_RECORD_BYTES
            || !keys.insert(chunk.key())
        {
            return Err(invariant("knowledge encoding chunk inventory changed"));
        }
        let _: serde_json::Value = decode(chunk.payload())?;
        if raw_checked(tx, chunk.key())?.is_some() {
            return Err(invariant(
                "knowledge encoding immutable chunk already exists",
            ));
        }
        bytes = bytes
            .checked_add(chunk.payload().len() as u64)
            .ok_or_else(|| invariant("knowledge encoding byte count exhausted"))?;
    }
    if bytes != proof.encoded_bytes()
        || usize::try_from(bytes)
            .map_err(|_| invariant("knowledge encoding byte count exhausted"))?
            > MAX_ENCODED_SET_BYTES
    {
        return Err(invariant(
            "knowledge encoding lost its actual complete footprint",
        ));
    }
    let old = raw_checked(tx, proof.root_key())?;
    let next_version = match (proof.expected_root(), old) {
        (Some(expected), Some(row)) => {
            verify_source_reference(tx, expected)?;
            require_encoding_header(tx, proof.root_key())?;
            if expected.record_key() != proof.root_key()
                || expected.scope_key() != proof.scope_key()
                || expected.kind() != "command"
                || row.kind != "command"
                || row.scope != proof.scope_key()
                || row.version != expected.version()
            {
                return Err(invariant("knowledge encoding lost its current root CAS"));
            }
            row.version
                .checked_add(1)
                .ok_or_else(|| invariant("knowledge encoding root version exhausted"))?
        }
        (None, None) => 1,
        _ => {
            return Err(invariant(
                "knowledge encoding root changed during admission",
            ))
        }
    };
    SafeInteger::new(next_version)
        .map_err(|_| invariant("knowledge encoding root version exhausted"))?;
    // This is the existing reversible intake observation. It does not claim
    // the unimplemented all-family debt bank or a filesystem space promise.
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    // Only the actual codec owner derives this complete body prefix. Lost
    // current rows, extra ordinals or retained event/global ghosts all refuse
    // before the first chunk or root append in this same fenced transaction.
    proof.verify_pristine_prefix(tx)?;
    for chunk in proof.staged_chunks() {
        persist_record(
            tx,
            owner,
            chunk.key(),
            chunk.scope(),
            "command",
            chunk.payload(),
            None,
        )?;
        let source = source_reference(tx, chunk.key())?;
        if source.version() != 1
            || source.kind() != "command"
            || source.scope_key() != chunk.scope()
        {
            return Err(invariant(
                "knowledge encoding chunk changed its immutable frame",
            ));
        }
        let row = raw_checked(tx, chunk.key())?
            .ok_or_else(|| invariant("knowledge encoding chunk disappeared"))?;
        if row.payload != chunk.payload() {
            return Err(invariant(
                "knowledge encoding chunk changed its exact bytes",
            ));
        }
        require_encoding_header(tx, chunk.key())?;
    }
    persist_record(
        tx,
        owner,
        proof.root_key(),
        proof.scope_key(),
        "command",
        proof.root_payload(),
        None,
    )?;
    let source = source_reference(tx, proof.root_key())?;
    if source.version() != next_version
        || source.kind() != "command"
        || source.scope_key() != proof.scope_key()
    {
        return Err(invariant(
            "knowledge encoding root changed its protected frame",
        ));
    }
    let row = raw_checked(tx, proof.root_key())?
        .ok_or_else(|| invariant("knowledge encoding root disappeared"))?;
    if row.payload != proof.root_payload() {
        return Err(invariant("knowledge encoding root changed its exact bytes"));
    }
    require_encoding_header(tx, proof.root_key())?;
    Ok((
        source,
        ProtectedMutationDelta {
            mutations: (proof.staged_chunks().len() as u64) + 1,
            encoded_bytes: bytes,
        },
    ))
}

fn require_encoding_format(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
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
            "knowledge encoding requires the current serving format",
        ));
    }
    Ok(())
}

fn require_encoding_header(tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
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
            "knowledge encoding metadata acquired a native request",
        ));
    }
    Ok(())
}
