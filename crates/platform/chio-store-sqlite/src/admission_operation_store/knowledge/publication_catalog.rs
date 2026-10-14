//! Read-only validation of retained native publication sources.
use super::*;

/// Current, historical and global keys are all selected before tenant filtering.
/// A disappeared projection cannot become a smaller live tenant count.
pub(in crate::admission_operation_store::knowledge) fn visit_publication_sources(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    mut visit: impl FnMut(
        &NativeArtifactRecordV1,
        &protected::ProtectedSourceReference,
    ) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-publication:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'knowledge-publication:*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let raw = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("publication census source disappeared"))?;
        let source = protected::source_reference(tx, &key)?;
        let record: NativeArtifactRecordV1 = protected::decode(&raw.payload)?;
        record.metadata.validate().map_err(refused)?;
        let ordinary: bool = tx.query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL FROM admission_operation_recovery_records WHERE record_key=?1",
            [&key], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !ordinary
            || raw.kind != "command"
            || raw.scope != scope_key(&record.metadata.scope)?
            || record_publication_key(&record)? != key
            || record.input.content != record.metadata.content
            || record.input.size_bytes != record.metadata.size_bytes
            || record.input.media_type != record.metadata.media_type
            || record.input.schema != record.metadata.schema
            || record.input.producer != record.metadata.producer
            || record.input.dependencies != record.metadata.dependencies
            || record.input.retention != record.metadata.retention
            || record.installation_generation.get() == 0
            || record.input.size_bytes.get() > MAX_ARTIFACT_BYTES as u64
        {
            return Err(refused(
                "publication census changed its full native identity",
            ));
        }
        if let Some(seal) = &record.seal {
            if seal.object != record.object
                || seal.process != record.metadata.scope.process_id
                || seal.content != record.input.content
                || seal.bytes != record.input.size_bytes
            {
                return Err(refused(
                    "publication census changed its original object seal",
                ));
            }
        } else if matches!(
            record.state,
            ArtifactPublicationStateV1::Staged
                | ArtifactPublicationStateV1::MetadataCommitted
                | ArtifactPublicationStateV1::Available
        ) {
            return Err(refused("publication census lost committed object custody"));
        }
        let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
        let pointer = load::<String>(tx, &version_key(&reference)?)?;
        if let Some(pointer) = &pointer {
            let pointer_source = protected::source_reference(tx, &version_key(&reference)?)?;
            if pointer != &key
                || pointer_source.version() != 1
                || pointer_source.kind() != "command"
                || pointer_source.scope_key() != raw.scope
                || !protected::matches_historical_command_payload(
                    tx,
                    pointer_source.record_key(),
                    &raw.scope,
                    1,
                    &protected::encode(pointer)?,
                )?
            {
                return Err(refused(
                    "publication census changed its immutable version pointer",
                ));
            }
        } else if matches!(
            record.state,
            ArtifactPublicationStateV1::MetadataCommitted | ArtifactPublicationStateV1::Available
        ) {
            return Err(refused("publication census lost its full governed version"));
        }
        if pointer.is_some()
            && matches!(
                record.state,
                ArtifactPublicationStateV1::Reserved | ArtifactPublicationStateV1::Staged
            )
        {
            return Err(refused(
                "publication census moved backward from metadata commitment",
            ));
        }
        if record.metadata.scope.authority_domain == scope.authority_domain
            && record.metadata.scope.tenant_id == scope.tenant_id
        {
            visit(&record, &source)?;
        }
    }
    Ok(())
}
