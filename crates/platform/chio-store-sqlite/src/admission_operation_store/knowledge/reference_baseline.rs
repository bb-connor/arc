//! A new artifact baseline exists only after its exact metadata commitment.
use super::references::{aggregate_key, reference_identity};
use super::*;
use std::ops::Deref;

pub(in crate::admission_operation_store) struct VerifiedNewArtifactReferenceBaseline<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    record: NativeArtifactRecordV1,
    reference: ArtifactVersionRefV1,
    publication: protected::ProtectedSourceReference,
    pointer: protected::ProtectedSourceReference,
}

impl<'tx, 'conn> VerifiedNewArtifactReferenceBaseline<'tx, 'conn> {
    /// Called by the owning metadata writer after certificate validation and
    /// exact version-pointer persistence, before publication becomes Available.
    pub(super) fn new(
        tx: &'tx Transaction<'conn>,
        record: &NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
        let witness = Self {
            transaction: tx,
            publication: protected::source_reference(tx, &record_publication_key(record)?)?,
            pointer: protected::source_reference(tx, &version_key(&reference)?)?,
            reference,
            record: record.clone(),
        };
        witness.verify(tx)?;
        Ok(witness)
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.reference
    }
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.publication
    }
    pub(in crate::admission_operation_store) fn pointer_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.pointer
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("new artifact baseline changed its physical writer"));
        }
        protected::verify_source_reference(tx, &self.publication)?;
        protected::verify_source_reference(tx, &self.pointer)?;
        self.record.metadata.validate().map_err(refused)?;
        let scope = scope_key(&self.reference.scope)?;
        let key = record_publication_key(&self.record)?;
        if self.record.state != ArtifactPublicationStateV1::MetadataCommitted
            || self.record.seal.is_none()
            || self.record.input.dependencies != self.record.metadata.dependencies
            || artifact_version_reference(&self.record.metadata).map_err(refused)? != self.reference
            || self.publication.record_key() != key
            || self.publication.scope_key() != scope
            || self.publication.kind() != "command"
            || self.pointer.record_key() != version_key(&self.reference)?
            || self.pointer.scope_key() != scope
            || self.pointer.kind() != "command"
            || self.pointer.version() != 1
        {
            return Err(refused(
                "new artifact baseline precedes exact metadata commitment",
            ));
        }
        let publication: NativeArtifactRecordV1 = load(tx, &key)?
            .ok_or_else(|| refused("new artifact baseline publication disappeared"))?;
        let pointer: String = load(tx, self.pointer.record_key())?
            .ok_or_else(|| refused("new artifact baseline pointer disappeared"))?;
        if protected::encode(&publication)? != protected::encode(&self.record)? || pointer != key {
            return Err(refused(
                "new artifact baseline changed its original publication",
            ));
        }
        if protected::raw_checked(tx, &aggregate_key(reference_identity(&self.reference)?))?
            .is_some()
        {
            return Err(refused(
                "new artifact baseline cannot reset retained references",
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for VerifiedNewArtifactReferenceBaseline<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedNewArtifactReferenceBaseline([redacted])")
    }
}
