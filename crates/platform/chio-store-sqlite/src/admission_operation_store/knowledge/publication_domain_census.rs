//! Authority-wide publication debt is distinct from a tenant's live quota.
use super::publication_census::PublicationForwardLiability;
use super::reference_source::ReferenceCutoff;
use super::*;
use std::ops::Deref;

/// This is one complete knowledge-family component of the physical domain
/// census. It cannot alone initialize the universal finishing meter.
pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationDomainBaseline<
    'tx,
    'conn,
> {
    transaction: &'tx Transaction<'conn>,
    domain: AuthorityDomainId,
    cutoff: ReferenceCutoff,
    liability: PublicationForwardLiability,
    census: CanonicalPayloadDigest,
}

/// Exact grandfathered phases preserve their actual current source version.
/// No initial Reserved row or version-one acceptance is invented for old work.
pub(in crate::admission_operation_store) struct PublicationDebtSource {
    record: NativeArtifactRecordV1,
    source: protected::ProtectedSourceReference,
    collected: Option<protected::ProtectedSourceReference>,
}

impl<'tx, 'conn> VerifiedKnowledgePublicationDomainBaseline<'tx, 'conn> {
    pub(super) fn capture(
        tx: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<Self, AdmissionOperationStoreError> {
        schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
        let cutoff = ReferenceCutoff::capture(tx, owner)?;
        let domain = AuthorityDomainId::new(&owner.fence.store_uuid).map_err(refused)?;
        let (liability, census) = census_domain(tx, &domain, &cutoff, |_| Ok(()))?;
        let proof = Self {
            transaction: tx,
            domain,
            cutoff,
            liability,
            census,
        };
        proof.verify(tx)?;
        Ok(proof)
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn authority_domain(&self) -> &AuthorityDomainId {
        &self.domain
    }
    pub(in crate::admission_operation_store) fn global_cutoff(&self) -> &ReferenceCutoff {
        &self.cutoff
    }
    pub(in crate::admission_operation_store) fn census_digest(&self) -> CanonicalPayloadDigest {
        self.census
    }
    pub(in crate::admission_operation_store) fn remaining_forward_liability_by_state(
        &self,
    ) -> &PublicationForwardLiability {
        &self.liability
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("publication domain census changed physical writer"));
        }
        self.cutoff.verify(tx)?;
        let (liability, census) = census_domain(tx, &self.domain, &self.cutoff, |_| Ok(()))?;
        if liability != self.liability || census != self.census {
            return Err(refused(
                "publication domain census changed authenticated debt",
            ));
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn visit_publications(
        &self,
        visit: impl FnMut(PublicationDebtSource) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify(self.transaction)?;
        let (liability, census) =
            census_domain(self.transaction, &self.domain, &self.cutoff, visit)?;
        if liability != self.liability || census != self.census {
            return Err(refused(
                "publication domain sources advanced during enrollment",
            ));
        }
        self.verify(self.transaction)
    }
}

impl PublicationDebtSource {
    pub(in crate::admission_operation_store) fn record(&self) -> &NativeArtifactRecordV1 {
        &self.record
    }
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }
    pub(in crate::admission_operation_store) fn collected_source(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.collected.as_ref()
    }
}

fn census_domain(
    tx: &Transaction<'_>,
    domain: &AuthorityDomainId,
    cutoff: &ReferenceCutoff,
    mut visit: impl FnMut(PublicationDebtSource) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(PublicationForwardLiability, CanonicalPayloadDigest), AdmissionOperationStoreError> {
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-publication:*'
         UNION SELECT projection_key FROM authority_global_commits
         WHERE projection_kind='recovery' AND projection_key GLOB 'knowledge-publication:*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut liability = PublicationForwardLiability::default();
    let mut census = CanonicalPayloadDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeReferenceOwner,
            &(domain, "publication_domain_debt", cutoff),
        )
        .map_err(refused)?,
    );
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let raw = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("publication domain source disappeared"))?;
        let source = protected::source_reference(tx, &key)?;
        let record: NativeArtifactRecordV1 = protected::decode(&raw.payload)?;
        record.metadata.validate().map_err(refused)?;
        let header_is_local: bool = tx
            .query_row(
                "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
                [&key],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if record_publication_key(&record)? != key
            || raw.kind != "command"
            || source.kind() != "command"
            || raw.scope != scope_key(&record.metadata.scope)?
            || source.scope_key() != raw.scope
            || !header_is_local
            || record.input.dependencies != record.metadata.dependencies
        {
            return Err(refused(
                "publication domain source lost exact native ownership",
            ));
        }
        if record.metadata.scope.authority_domain != *domain {
            continue;
        }
        if source.global_commit_sequence() > cutoff.sequence() {
            return Err(refused(
                "publication domain source moved beyond cold cutoff",
            ));
        }
        let collected = lifecycle::publication_collection_source(tx, &record)?;
        if collected
            .as_ref()
            .is_some_and(|source| source.global_commit_sequence() > cutoff.sequence())
        {
            return Err(refused(
                "publication domain collection moved beyond cold cutoff",
            ));
        }
        census = CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeReferenceOwner,
                &(
                    census,
                    &key,
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
        if collected.is_none() {
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
                .ok_or_else(|| refused("publication domain debt exhausted"))?;
        }
        visit(PublicationDebtSource {
            record,
            source,
            collected,
        })?;
    }
    Ok((liability, census))
}

impl std::fmt::Debug for VerifiedKnowledgePublicationDomainBaseline<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgePublicationDomainBaseline([redacted])")
    }
}
impl std::fmt::Debug for PublicationDebtSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicationDebtSource([redacted])")
    }
}
