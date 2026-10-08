//! A complete scoped reference closure is evidence, never a collection grant.
use super::*;
use std::ops::Deref;

pub(in crate::admission_operation_store) struct CollectedPublicationReferenceClosure<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    record: NativeArtifactRecordV1,
    sources: Vec<protected::ProtectedSourceReference>,
}

/// The caller must separately prove the native collected disposition before
/// refunding a publication lease. Neither Retired nor this closure proves that
/// the host acknowledged deletion of the original private object.
pub(in crate::admission_operation_store) fn collected_publication_closure<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    record: &NativeArtifactRecordV1,
) -> Result<CollectedPublicationReferenceClosure<'tx, 'conn>, AdmissionOperationStoreError> {
    let sources = collection_sources(tx, record)?;
    Ok(CollectedPublicationReferenceClosure {
        transaction: tx,
        record: record.clone(),
        sources,
    })
}

impl<'tx, 'conn> CollectedPublicationReferenceClosure<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn authenticated_sources(
        &self,
    ) -> &[protected::ProtectedSourceReference] {
        &self.sources
    }

    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("publication closure changed its physical writer"));
        }
        for source in &self.sources {
            protected::verify_source_reference(tx, source)?;
        }
        // Recheck readiness and full typed closure as well as old source heads.
        // This cannot manufacture a zero from a missing row or stale pointer.
        collection_sources(tx, &self.record)?;
        Ok(())
    }
}

pub(in crate::admission_operation_store::knowledge) fn collection_sources(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<Vec<protected::ProtectedSourceReference>, AdmissionOperationStoreError> {
    if record.state != ArtifactPublicationStateV1::Retired
        || record.input.dependencies != record.metadata.dependencies
    {
        return Err(refused("publication closure is not retired"));
    }
    let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
    let publication_key = record_publication_key(record)?;
    let publication =
        reader::indexed::<NativeArtifactRecordV1>(tx, &publication_key, &record.metadata.scope)?
            .ok_or_else(|| refused("publication closure lost its owning source"))?;
    let pointer = reader::indexed::<String>(tx, &version_key(&reference)?, &record.metadata.scope)?;
    let encoded = protected::encode(record)?;
    if protected::encode(&publication.value)? != encoded
        || pointer
            .as_ref()
            .is_some_and(|pointer| pointer.value != publication_key)
    {
        return Err(refused(
            "publication closure changed its metadata or pointer",
        ));
    }
    let terminal_sequence = publication.head.global_commit_sequence();
    let mut sources = Vec::new();
    if let Some(pointer) = pointer {
        let root = load_reference_state(tx, &reference)?;
        if root.aggregate.value.collection_count()? != 0
            || super::super::lifecycle::pinned(tx, &reference)?
        {
            return Err(refused(
                "publication closure retains active reference owners",
            ));
        }
        sources.push(pointer.head);
        sources.push(root.aggregate.head);
        sources.extend(root.buckets.into_iter().map(|bucket| bucket.head));
    } else {
        // An aborted staging object never became a governed version. Preserve
        // absence provenance rather than manufacturing a pointer or root.
        let mut initial = record.clone();
        initial.state = ArtifactPublicationStateV1::Reserved;
        initial.seal = None;
        initial.certificate = None;
        initial.location = ProtectedText::new("private-process-blob").map_err(refused)?;
        if record.certificate.is_some()
            || matches!(
                record.metadata.producer,
                ArtifactProducerV1::NativeOperation { .. }
            )
            || !protected::matches_historical_source_command_payload(
                tx,
                &publication.head,
                1,
                &protected::encode(&initial)?,
            )?
        {
            return Err(refused(
                "uncommitted collection lacks original reservation custody",
            ));
        }
        require_uncommitted_reference_absence(tx, &reference)?;
    }
    sources.push(publication.head);
    let owner = ReferenceOwner::Publication {
        scope: record.metadata.scope.clone(),
        artifact: record.metadata.artifact.clone(),
        version: record.metadata.version.clone(),
    };
    for dependency in record.input.dependencies.as_slice() {
        let state = load_reference_state(tx, dependency)?;
        let Some(leaf) = load_owner_leaf(tx, dependency, &owner, &state)? else {
            let ReferenceBaselineSource::Cold { cutoff, .. } =
                &state.aggregate.value.baseline.source
            else {
                return Err(refused("publication closure lacks its dependency owner"));
            };
            if terminal_sequence > cutoff.sequence()
                && super::super::publication_capacity::collection::retired_source_before(
                    tx,
                    record,
                    cutoff
                        .sequence()
                        .checked_add(1)
                        .ok_or_else(|| refused("publication cold cutoff exhausted"))?,
                )?
                .is_none()
            {
                return Err(refused(
                    "publication dependency lacks an authentic cold retirement",
                ));
            }
            sources.push(state.aggregate.head);
            sources.extend(state.buckets.into_iter().map(|bucket| bucket.head));
            continue;
        };
        if leaf.value.state != ReferenceOwnerState::Retired {
            return Err(refused(
                "publication closure retains a direct dependency owner",
            ));
        }
        sources.push(leaf.head);
        sources.push(state.aggregate.head);
        sources.extend(state.buckets.into_iter().map(|bucket| bucket.head));
    }
    Ok(sources)
}

fn require_uncommitted_reference_absence(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<(), AdmissionOperationStoreError> {
    let identity = reference_identity(reference)?;
    for pattern in [
        aggregate_key(identity),
        format!(
            "knowledge-reference-owner:{}:*",
            hex::encode(identity.as_bytes())
        ),
        format!(
            "knowledge-reference-bucket:{}:*",
            hex::encode(identity.as_bytes())
        ),
    ] {
        let retained: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB ?1)
             OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB ?1)
             OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB ?1)",
            [pattern], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if retained {
            return Err(refused(
                "uncommitted collection retained a governed reference index",
            ));
        }
    }
    Ok(())
}

impl std::fmt::Debug for CollectedPublicationReferenceClosure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CollectedPublicationReferenceClosure([redacted])")
    }
}
