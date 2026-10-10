//! One authenticated Restore fixture can retain its exact extra chunk ordinal.
//! This child and export exist only with admission-test-support enabled.
use super::*;
use crate::admission_operation_store::knowledge::encoding::chunks::ChunkedBody;
use crate::admission_operation_store::knowledge::AuthenticatedCheckpointRestoreEncodingSource;

/// The owning Restore source independently requires its exact selected
/// Uncertain acknowledgement and actual logical body. No raw key, payload,
/// family selector or caller-built native authority enters this fixture seam.
pub(in crate::admission_operation_store) fn retain_restore_extra_ordinal_fixture<'tx, 'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    source: &AuthenticatedCheckpointRestoreEncodingSource<'tx, 'conn>,
    body: &ChunkedBody,
) -> Result<ProtectedSourceReference, AdmissionOperationStoreError> {
    require_encoding_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if !std::ptr::eq::<Connection>(Deref::deref(source.transaction()), Deref::deref(tx))
        || body.owner() != &source.owner()
        || body.owner().scope().authority_domain.as_str() != owner.fence.store_uuid
    {
        return Err(invariant(
            "extra chunk fixture changed its actual Restore writer",
        ));
    }
    source.verify(tx)?;
    body.validate()?;
    // Both cfg-only codec methods belong to the actual Restore/ChunkedBody
    // owners. The source rederives its whole exact logical record and permits
    // only Uncertain ACK; the frame is exactly N, with N+1 and N*65536+1.
    source.verify_extra_ordinal_fixture(tx, body)?;
    let chunk = body.extra_ordinal_fixture()?;
    let prefix = body.chunk_prefix()?;
    if chunk.key().is_empty()
        || chunk.key().len() > 512
        || !chunk.key().starts_with(&prefix)
        || chunk.scope() != scope_key(body.owner().scope())?
        || chunk.payload().is_empty()
        || chunk.payload().len() > MAX_RECOVERY_RECORD_BYTES
        || raw_checked(tx, chunk.key())?.is_some()
    {
        return Err(invariant(
            "extra chunk fixture changed its closed canonical frame",
        ));
    }
    let _: serde_json::Value = decode(chunk.payload())?;
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    // The fixed owner and codec factory, not a public raw-SQL fixture, supply
    // this one ordinary command-kind immutable row in the original writer.
    persist_record(
        tx,
        owner,
        chunk.key(),
        chunk.scope(),
        "command",
        chunk.payload(),
        None,
    )?;
    let reference = source_reference(tx, chunk.key())?;
    let row = raw_checked(tx, chunk.key())?
        .ok_or_else(|| invariant("extra chunk fixture lost its retained source"))?;
    require_encoding_header(tx, chunk.key())?;
    if reference.version() != 1
        || reference.kind() != "command"
        || reference.scope_key() != chunk.scope()
        || row.version != 1
        || row.kind != "command"
        || row.scope != chunk.scope()
        || row.payload != chunk.payload()
    {
        return Err(invariant(
            "extra chunk fixture changed its exact retained bytes",
        ));
    }
    Ok(reference)
}
