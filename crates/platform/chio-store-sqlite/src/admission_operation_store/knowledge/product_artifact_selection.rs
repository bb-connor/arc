//! A public Product selector distinguishes refusal from retained corruption.
//! The returned metadata grants no bytes, read, reference, cleanup or loan role.
use super::*;

pub(in crate::admission_operation_store) fn selected_product_artifact(
    tx: &Connection,
    requested: &ArtifactVersionRefV1,
) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
    let record = authenticated_product_artifact(tx, requested)?;
    if record.state != ArtifactPublicationStateV1::Available {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(record)
}

/// Exact retained Product replay observes metadata only. The Product caller
/// must separately authenticate its immutable source and current audience.
/// This selector cannot admit fresh references or recover private bytes.
pub(in crate::admission_operation_store) fn retained_product_artifact(
    tx: &Connection,
    requested: &ArtifactVersionRefV1,
) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
    let record = authenticated_product_artifact(tx, requested)?;
    if !matches!(
        record.state,
        ArtifactPublicationStateV1::Available
            | ArtifactPublicationStateV1::Quarantined
            | ArtifactPublicationStateV1::Retired
    ) {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(record)
}

fn authenticated_product_artifact(
    tx: &Connection,
    requested: &ArtifactVersionRefV1,
) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
    let pointer_key = version_key(requested)?;
    let Some(pointer_row) = protected::raw_checked(tx, &pointer_key)? else {
        // raw_checked has already refused missing current with any retained
        // event/global ownership. Only pristine caller selection is denied.
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    };
    let pointer = protected::source_reference(tx, &pointer_key)?;
    let publication_key: String = protected::decode(&pointer_row.payload)?;
    let scope = scope_key(&requested.scope)?;
    if pointer_row.version != 1
        || pointer.version() != 1
        || pointer_row.kind != "command"
        || pointer.kind() != "command"
        || pointer_row.scope != scope
        || pointer.scope_key() != scope
        || pointer.record_key() != pointer_key
        || publication_key.is_empty()
        || publication_key.len() > 512
        || protected::encode(&publication_key)? != pointer_row.payload
    {
        return Err(refused(
            "product selected pointer lost its native provenance",
        ));
    }
    require_local_frame(tx, &pointer_key)?;
    // A retained pointer requires its real publication. Even pristine absence
    // of that target is an operational integrity error, never caller refusal.
    let publication_row = protected::raw_checked(tx, &publication_key)?
        .ok_or_else(|| refused("product selected publication disappeared"))?;
    let publication = protected::source_reference(tx, &publication_key)?;
    let record: NativeArtifactRecordV1 = protected::decode(&publication_row.payload)?;
    record.metadata.validate().map_err(refused)?;
    if publication.kind() != "command"
        || publication_row.kind != "command"
        || publication.scope_key() != scope
        || publication_row.scope != scope
        || publication.version() != publication_row.version
        || publication.record_key() != publication_key
        || record_publication_key(&record)? != publication_key
        || record.metadata.scope != requested.scope
        || record.metadata.artifact != requested.artifact
        || record.metadata.version != requested.version
        || record.input.content != record.metadata.content
        || record.input.size_bytes != record.metadata.size_bytes
        || record.input.media_type != record.metadata.media_type
        || record.input.schema != record.metadata.schema
        || record.input.producer != record.metadata.producer
        || record.input.dependencies != record.metadata.dependencies
        || record.input.retention != record.metadata.retention
        || protected::encode(&record)? != publication_row.payload
    {
        return Err(refused(
            "product selected publication lost its native provenance",
        ));
    }
    require_local_frame(tx, &publication_key)?;
    protected::verify_source_reference(tx, &pointer)?;
    protected::verify_source_reference(tx, &publication)?;
    // Exact canonical source custody and its own scope/id/version were proved
    // before comparing caller-supplied governed provenance or availability.
    if artifact_version_reference(&record.metadata).map_err(refused)? != *requested {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(record)
}

fn require_local_frame(tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
    let local: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
         FROM main.admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !local {
        return Err(refused("product selected artifact changed native framing"));
    }
    Ok(())
}
