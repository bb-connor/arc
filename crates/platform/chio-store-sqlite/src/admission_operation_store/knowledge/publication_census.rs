//! Legacy live accounting starts from complete authenticated publication custody.
use super::reference_source::ReferenceCutoff;
use super::*;
use std::ops::Deref;

#[derive(Default, Eq, PartialEq, Serialize)]
pub(in crate::admission_operation_store) struct PublicationForwardLiability {
    pub reserved: u64,
    pub staged: u64,
    pub metadata_committed: u64,
    pub available: u64,
    pub quarantined: u64,
    pub retired_pending_collection: u64,
}

pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationBaseline<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    scope: RecoveryScopeV1,
    cutoff: ReferenceCutoff,
    active_publications: u64,
    liability: PublicationForwardLiability,
    census: CanonicalPayloadDigest,
}

impl<'tx, 'conn> VerifiedKnowledgePublicationBaseline<'tx, 'conn> {
    pub(super) fn for_installation(
        tx: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
        profile: &NativeKnowledgeInstallationV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let recovery = protected::deployment_tx(tx, &profile.scope)?;
        validate_installation(tx, &recovery, profile)?;
        let current = installation(tx, &profile.scope)?;
        if protected::encode(&current)? != protected::encode(profile)? {
            return Err(refused("publication census installation changed"));
        }
        let cutoff = ReferenceCutoff::capture(tx, owner)?;
        let (active_publications, liability, census) =
            census_publications(tx, &profile.scope, &cutoff)?;
        Ok(Self {
            transaction: tx,
            scope: profile.scope.clone(),
            cutoff,
            active_publications,
            liability,
            census,
        })
    }

    pub(in crate::admission_operation_store) fn active_publications(&self) -> u64 {
        self.active_publications
    }
    pub(in crate::admission_operation_store) fn remaining_forward_liability_by_state(
        &self,
    ) -> &PublicationForwardLiability {
        &self.liability
    }
    pub(in crate::admission_operation_store) fn global_cutoff(&self) -> &ReferenceCutoff {
        &self.cutoff
    }
    pub(in crate::admission_operation_store) fn census_digest(&self) -> CanonicalPayloadDigest {
        self.census
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("publication census changed its physical writer"));
        }
        self.cutoff.verify(tx)?;
        let (active, liability, census) = census_publications(tx, &self.scope, &self.cutoff)?;
        if active != self.active_publications
            || liability != self.liability
            || census != self.census
        {
            return Err(refused("publication census changed its retained sources"));
        }
        Ok(())
    }
}

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

fn census_publications(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    cutoff: &ReferenceCutoff,
) -> Result<(u64, PublicationForwardLiability, CanonicalPayloadDigest), AdmissionOperationStoreError>
{
    let mut active = 0_u64;
    let mut liability = PublicationForwardLiability::default();
    let mut census = CanonicalPayloadDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeReferenceOwner,
            &(
                "publication_live_census",
                &scope.authority_domain,
                &scope.tenant_id,
                cutoff,
            ),
        )
        .map_err(refused)?,
    );
    visit_publication_sources(tx, scope, |record, source| {
        if source.global_commit_sequence() > cutoff.sequence() {
            return Err(refused("publication census moved beyond its cutoff"));
        }
        let collected = super::publication_capacity::collection::collected_source(tx, record)?;
        if collected
            .as_ref()
            .is_some_and(|source| source.global_commit_sequence() > cutoff.sequence())
        {
            return Err(refused(
                "publication collection moved beyond its census cutoff",
            ));
        }
        census = CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeReferenceOwner,
                &(
                    census,
                    super::references::SourceAnchor::capture(source),
                    &collected,
                ),
            )
            .map_err(refused)?,
        );
        if collected.is_some() {
            return Ok(());
        }
        active = active
            .checked_add(1)
            .ok_or_else(|| refused("publication census overflow"))?;
        let phase = match record.state {
            ArtifactPublicationStateV1::Reserved => &mut liability.reserved,
            ArtifactPublicationStateV1::Staged => &mut liability.staged,
            ArtifactPublicationStateV1::MetadataCommitted => &mut liability.metadata_committed,
            ArtifactPublicationStateV1::Available => &mut liability.available,
            ArtifactPublicationStateV1::Quarantined => &mut liability.quarantined,
            ArtifactPublicationStateV1::Retired => &mut liability.retired_pending_collection,
        };
        *phase = phase
            .checked_add(1)
            .ok_or_else(|| refused("publication phase overflow"))?;
        Ok(())
    })?;
    Ok((active, liability, census))
}

impl std::fmt::Debug for VerifiedKnowledgePublicationBaseline<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgePublicationBaseline([redacted])")
    }
}
