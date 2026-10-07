//! Legacy publication accounting is activated from authenticated cold custody.
use super::reference_source::ReferenceCutoff;
use super::*;
use std::ops::Deref;

/// Counts describe native states. Only the allocator applies its closed byte
/// and write-envelope contract; decoding a count supplies no reserve class.
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
    /// Explicit host activation after the complete native installation has been
    /// authenticated in this transaction. This is never a hot missing-row path.
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

fn census_publications(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    cutoff: &ReferenceCutoff,
) -> Result<(u64, PublicationForwardLiability, CanonicalPayloadDigest), AdmissionOperationStoreError>
{
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'
             UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-publication:*'
             UNION SELECT projection_key FROM authority_global_commits
             WHERE projection_kind='recovery' AND projection_key GLOB 'knowledge-publication:*' ORDER BY 1",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut active = 0_u64;
    let mut liability = PublicationForwardLiability::default();
    let mut census = CanonicalPayloadDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeReferenceOwner,
            &(&scope.authority_domain, &scope.tenant_id, cutoff),
        )
        .map_err(refused)?,
    );
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let source = protected::source_reference(tx, &key)?;
        let raw = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("publication census source disappeared"))?;
        let record: NativeArtifactRecordV1 = protected::decode(&raw.payload)?;
        record.metadata.validate().map_err(refused)?;
        if raw.kind != "command"
            || raw.scope != scope_key(&record.metadata.scope)?
            || record_publication_key(&record)? != key
        {
            return Err(refused("publication census lost its exact source identity"));
        }
        if record.metadata.scope.authority_domain != scope.authority_domain
            || record.metadata.scope.tenant_id != scope.tenant_id
        {
            continue;
        }
        if source.global_commit_sequence() > cutoff.sequence() {
            return Err(refused("publication census moved beyond its cutoff"));
        }
        let collected = lifecycle::publication_collection_source(tx, &record)?;
        census = CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeReferenceOwner,
                &(
                    census,
                    key,
                    source.version(),
                    source.digest(),
                    source.event_sequence(),
                    source.global_commit_sequence(),
                    collected.as_ref().map(|source| {
                        (
                            source.record_key(),
                            source.version(),
                            source.digest(),
                            source.event_sequence(),
                            source.global_commit_sequence(),
                        )
                    }),
                ),
            )
            .map_err(refused)?,
        );
        if collected.is_some() {
            continue;
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
    }
    Ok((active, liability, census))
}

impl std::fmt::Debug for VerifiedKnowledgePublicationBaseline<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgePublicationBaseline([redacted])")
    }
}
