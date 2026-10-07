//! Original protected release custody supplies data for exact reference owners.
use super::*;

/// No deserialized state can construct this source. Every field is derived from
/// the exact protected original handle, intent and immutable native observation.
pub(in crate::admission_operation_store::knowledge) struct ArtifactReleaseReferenceSource {
    scope: RecoveryScopeV1,
    release: ReleaseId,
    references: Vec<ArtifactVersionRefV1>,
    envelope: CanonicalPayloadDigest,
    source: protected::ProtectedSourceReference,
    supporting_sources: Vec<protected::ProtectedSourceReference>,
    delivered: bool,
}

impl ArtifactReleaseReferenceSource {
    pub(in crate::admission_operation_store::knowledge) fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub(in crate::admission_operation_store::knowledge) fn release(&self) -> &ReleaseId {
        &self.release
    }
    pub(in crate::admission_operation_store::knowledge) fn references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        &self.references
    }
    pub(in crate::admission_operation_store::knowledge) fn envelope(
        &self,
    ) -> CanonicalPayloadDigest {
        self.envelope
    }
    pub(in crate::admission_operation_store::knowledge) fn active(&self) -> bool {
        !self.delivered
    }
    pub(in crate::admission_operation_store::knowledge) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }
    pub(in crate::admission_operation_store::knowledge) fn supporting_sources(
        &self,
    ) -> &[protected::ProtectedSourceReference] {
        &self.supporting_sources
    }
    pub(in crate::admission_operation_store::knowledge) fn terminal(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.delivered.then_some(&self.source)
    }
}

pub(in crate::admission_operation_store::knowledge) fn artifact_reference_source(
    tx: &Connection,
    key: &str,
) -> Result<Option<ArtifactReleaseReferenceSource>, AdmissionOperationStoreError> {
    if !key.starts_with("knowledge-release:") {
        return Ok(None);
    }
    let Some(row) = protected::raw_checked(tx, key)? else {
        return Ok(None);
    };
    let record: ReleaseRecord = protected::decode(&row.payload)?;
    let scope = &record.intent.artifact.scope;
    let scope_identity = scope_key(scope)?;
    let source = protected::source_reference(tx, key)?;
    let original_handle_key = handle_key(scope, &record.handle.handle)?;
    let handle: HandleRecord =
        load(tx, &original_handle_key)?.ok_or_else(|| refused("release original handle absent"))?;
    let handle_source = protected::source_reference(tx, &original_handle_key)?;
    let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &record.intent.kind else {
        return Err(refused("artifact release selected captured-output custody"));
    };
    if (key != actor_request_key("knowledge-release", scope, &handle.principal, request)?
        && key != legacy_release_key(scope, request)?)
        || row.kind != "command"
        || row.scope != scope_identity
        || source.scope_key() != scope_identity
        || source.kind() != "command"
        || handle_source.scope_key() != scope_identity
        || handle_source.kind() != "command"
        || handle_source.version() != 1
        || handle.handle != record.handle
        || handle.artifact != record.intent.artifact
        || handle.recipient != record.intent.recipient
        || handle.handle.recipient != record.intent.recipient.recipient
        || record.intent.recipient.scope != *scope
        || record.capability != record.intent.authorization
    {
        return Err(refused(
            "release changed exact original handle or authority",
        ));
    }
    for identity in [key, original_handle_key.as_str()] {
        let local: bool = tx
            .query_row(
                "SELECT native_namespace IS NULL AND native_request IS NULL
                 FROM admission_operation_recovery_records WHERE record_key=?1",
                [identity],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !local {
            return Err(refused("release changed its original protected frame"));
        }
    }
    if !protected::matches_historical_command_payload(
        tx,
        &original_handle_key,
        &scope_identity,
        1,
        &protected::encode(&handle)?,
    )? {
        return Err(refused("release changed its immutable original handle"));
    }
    let mut admitted = record.clone();
    admitted.intent.state = ArtifactDeliveryStateV1::Admitted;
    let admitted_bytes = protected::encode(&admitted)?;
    if !protected::matches_historical_command_payload(tx, key, &scope_identity, 1, &admitted_bytes)?
    {
        return Err(refused("release changed its immutable original intent"));
    }
    let observation =
        super::super::super::security_participant_state::knowledge::release_observation_source(
            tx,
            &record.intent,
        )?;
    let original_commit = protected::historical_record_commit(tx, key, 1)?;
    if handle_source.global_commit_sequence() >= observation.global_commit_sequence()
        || observation.global_commit_sequence() >= original_commit
    {
        return Err(refused("release changed its original native custody order"));
    }
    let mut supporting_sources = vec![handle_source, observation];
    let mut pending = vec![record.intent.artifact.clone()];
    if let ArtifactSinkV1::Model { context } = &record.intent.recipient.sink {
        pending.extend_from_slice(context.side_files.as_slice());
    }
    let mut references = Vec::new();
    while let Some(reference) = pending.pop() {
        if reference.scope != *scope {
            return Err(refused("release retained dependency crossed process"));
        }
        if references.contains(&reference) {
            continue;
        }
        if references.len() == MAX_ARTIFACT_TRAVERSAL {
            return Err(refused("release retained dependency inventory overflow"));
        }
        let pointer_key = version_key(&reference)?;
        let publication: String =
            load(tx, &pointer_key)?.ok_or_else(|| refused("release artifact pointer absent"))?;
        let material: NativeArtifactRecordV1 =
            load(tx, &publication)?.ok_or_else(|| refused("release artifact material absent"))?;
        material.metadata.validate().map_err(refused)?;
        if record_publication_key(&material)? != publication
            || artifact_version_reference(&material.metadata).map_err(refused)? != reference
            || material.input.dependencies != material.metadata.dependencies
        {
            return Err(refused(
                "release changed full retained dependency provenance",
            ));
        }
        let pointer = protected::source_reference(tx, &pointer_key)?;
        let publication_source = protected::source_reference(tx, &publication)?;
        for material_source in [&pointer, &publication_source] {
            if material_source.kind() != "command" || material_source.scope_key() != scope_identity
            {
                return Err(refused("release retained material changed protected scope"));
            }
        }
        if pointer.version() != 1
            || !protected::matches_historical_command_payload(
                tx,
                &pointer_key,
                &scope_identity,
                1,
                &protected::encode(&publication)?,
            )?
        {
            return Err(refused(
                "release changed immutable retained version pointer",
            ));
        }
        pending.extend_from_slice(material.metadata.dependencies.as_slice());
        if pending.len() > MAX_ARTIFACT_TRAVERSAL * MAX_ARTIFACT_DEPENDENCIES {
            return Err(refused("release retained dependency work overflow"));
        }
        supporting_sources.push(pointer);
        supporting_sources.push(publication_source);
        references.push(reference);
    }
    Ok(Some(ArtifactReleaseReferenceSource {
        scope: scope.clone(),
        release: record.intent.release,
        references,
        envelope: CanonicalPayloadDigest::from_bytes(
            *chio_core::sha256(&admitted_bytes).as_bytes(),
        ),
        source,
        supporting_sources,
        delivered: record.intent.state == ArtifactDeliveryStateV1::Delivered,
    }))
}
