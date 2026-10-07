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

fn collection_sources(
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
    let pointer = reader::indexed::<String>(tx, &version_key(&reference)?, &record.metadata.scope)?
        .ok_or_else(|| refused("publication closure lost its exact version pointer"))?;
    let encoded = protected::encode(record)?;
    if protected::encode(&publication.value)? != encoded || pointer.value != publication_key {
        return Err(refused(
            "publication closure changed its metadata or pointer",
        ));
    }
    let root = load_reference_state(tx, &reference)?;
    if root.aggregate.value.collection_count()? != 0 {
        return Err(refused(
            "publication closure retains active reference owners",
        ));
    }
    let mut sources = vec![publication.head, pointer.head, root.aggregate.head];
    sources.extend(root.buckets.into_iter().map(|bucket| bucket.head));
    let owner = ReferenceOwner::Publication {
        scope: record.metadata.scope.clone(),
        artifact: record.metadata.artifact.clone(),
        version: record.metadata.version.clone(),
    };
    for dependency in record.input.dependencies.as_slice() {
        let state = load_reference_state(tx, dependency)?;
        let leaf = load_owner_leaf(tx, dependency, &owner, &state)?
            .ok_or_else(|| refused("publication closure lacks its dependency owner"))?;
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

impl std::fmt::Debug for CollectedPublicationReferenceClosure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CollectedPublicationReferenceClosure([redacted])")
    }
}
