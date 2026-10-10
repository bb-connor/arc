//! Bounded reference reads require a complete native account activation.
use super::references::SourceAnchor;
use super::*;

/// Only the actual metadata writer calls this, after the certificate, complete
/// publication body and exact immutable pointer have committed in this Tx.
pub(super) fn initialize_committed_artifact_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &NativeArtifactRecordV1,
) -> Result<protected::ProtectedMutationDelta, AdmissionOperationStoreError> {
    let source = super::reference_baseline::VerifiedNewArtifactReferenceBaseline::new(tx, record)?;
    let plan = super::references::prepare_new_artifact_reference_baseline(tx, source)?;
    let (_, delta) = protected::persist_knowledge_new_artifact_reference_baseline(tx, owner, plan)?;
    Ok(delta)
}

/// The enclosing owning read has already authenticated its serving transaction.
/// A missing or historical-only marker is never interpreted as empty custody.
pub(in crate::admission_operation_store) fn verify_reference_ready(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(), AdmissionOperationStoreError> {
    super::references::ready_reference_account(tx, scope)?.verify_current(tx)
}

/// The immutable first aggregate is separately matched against protected
/// history by the index reader. This verifies its typed source and the exact
/// governed version pointer without rewriting a historical envelope.
pub(in crate::admission_operation_store) fn verify_reference_baseline(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    source: &SourceAnchor,
) -> Result<(), AdmissionOperationStoreError> {
    let ready = super::references::ready_reference_account(tx, &reference.scope)?;
    let (_, publication, pointer) = retained_reference_artifact(tx, reference)?;
    source.validate_ordinary()?;
    source.verify_historical_identity(tx)?;
    if source.record_key() != publication.record_key()
        || source.scope_key() != publication.scope_key()
        || !source.not_after(&SourceAnchor::capture(&publication))
        || source.global_commit_sequence() <= ready.cutoff().sequence()
        || pointer.global_commit_sequence() <= ready.cutoff().sequence()
    {
        return Err(refused("reference baseline changed its metadata source"));
    }
    Ok(())
}

fn retained_reference_artifact(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<
    (
        NativeArtifactRecordV1,
        protected::ProtectedSourceReference,
        protected::ProtectedSourceReference,
    ),
    AdmissionOperationStoreError,
> {
    let key = version_key(reference)?;
    let pointer: String =
        load(tx, &key)?.ok_or_else(|| refused("reference baseline version disappeared"))?;
    let record: NativeArtifactRecordV1 =
        load(tx, &pointer)?.ok_or_else(|| refused("reference baseline publication disappeared"))?;
    record.metadata.validate().map_err(refused)?;
    let publication = protected::source_reference(tx, &pointer)?;
    let version = protected::source_reference(tx, &key)?;
    let scope = scope_key(&reference.scope)?;
    if record_publication_key(&record)? != pointer
        || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
        || publication.kind() != "command"
        || publication.scope_key() != scope
        || version.kind() != "command"
        || version.scope_key() != scope
        || version.version() != 1
        || !protected::matches_historical_command_payload(
            tx,
            &key,
            &scope,
            1,
            &protected::encode(&pointer)?,
        )?
    {
        return Err(refused(
            "reference baseline changed its full governed version",
        ));
    }
    Ok((record, publication, version))
}
