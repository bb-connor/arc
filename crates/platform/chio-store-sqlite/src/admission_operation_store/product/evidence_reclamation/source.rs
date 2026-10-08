//! Terminal source data authenticates the full immutable tuple without minting a writer.
use super::*;

pub(in crate::admission_operation_store) struct ProductEvidenceReclamationSource {
    owner: ProductEvidenceOwner,
    original: protected::ProtectedSourceReference,
    archive: protected::ProtectedSourceReference,
    terminal: protected::ProtectedSourceReference,
    references: Vec<ArtifactVersionRefV1>,
}

impl ProductEvidenceReclamationSource {
    pub(in crate::admission_operation_store) fn owner(&self) -> &ProductEvidenceOwner {
        &self.owner
    }
    pub(in crate::admission_operation_store) fn original(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.original
    }
    pub(in crate::admission_operation_store) fn archive(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.archive
    }
    pub(in crate::admission_operation_store) fn terminal(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.terminal
    }
    pub(in crate::admission_operation_store) fn references(&self) -> &[ArtifactVersionRefV1] {
        &self.references
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let current = product_reclamation_source(tx, &self.owner)?
            .ok_or_else(|| refused("proposal reclamation terminal disappeared"))?;
        if current.owner != self.owner
            || current.references != self.references
            || SourceAnchor::capture(&current.original) != SourceAnchor::capture(&self.original)
            || SourceAnchor::capture(&current.archive) != SourceAnchor::capture(&self.archive)
            || SourceAnchor::capture(&current.terminal) != SourceAnchor::capture(&self.terminal)
        {
            return Err(refused("proposal reclamation source tuple changed"));
        }
        Ok(())
    }
}

pub(in crate::admission_operation_store) fn product_reclamation_source(
    tx: &Connection,
    owner: &ProductEvidenceOwner,
) -> Result<Option<ProductEvidenceReclamationSource>, AdmissionOperationStoreError> {
    let ProductEvidenceOwner::Proposal { scope, id, digest } = owner else {
        return Err(refused("only Proposal evidence has a reclamation terminal"));
    };
    let key = reclamation_key(scope, id)?;
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let terminal = immutable_local_source(tx, scope, &key)?;
    let value: ReclaimedProposalEvidence = protected::decode(&row.payload)?;
    if value.scope != *scope
        || value.proposal_id != *id
        || value.proposal_digest != *digest
        || protected::encode(&value)? != row.payload
    {
        return Err(refused("proposal reclamation terminal identity"));
    }
    let proposal = stored_proposal(tx, scope, id)?;
    let (original, references) = product_evidence_source(tx, owner)?;
    let (archive, archived_at) = lifecycle::archived_proposal_source(tx, &proposal)?
        .ok_or_else(|| refused("reclamation lacks its actual Proposal archive"))?;
    let original = immutable_local_source(tx, scope, original.record_key())?;
    let archive = immutable_local_source(tx, scope, archive.record_key())?;
    value.original.validate_ordinary()?;
    value.archive.validate_ordinary()?;
    if value.original != SourceAnchor::capture(&original)
        || value.archive != SourceAnchor::capture(&archive)
        || proposal.digest != *digest
        || references.is_empty()
        || references.len() > 32
        || archived_at < proposal.submitted_at_unix_ms.get()
        || value.reclaimed_at_unix_ms.get() < archived_at
        || original.event_sequence() >= archive.event_sequence()
        || archive.event_sequence() >= terminal.event_sequence()
        || original.global_commit_sequence() >= archive.global_commit_sequence()
        || archive.global_commit_sequence() >= terminal.global_commit_sequence()
    {
        return Err(refused(
            "proposal reclamation lost its original archive custody",
        ));
    }
    Ok(Some(ProductEvidenceReclamationSource {
        owner: owner.clone(),
        original,
        archive,
        terminal,
        references,
    }))
}

/// Current rows alone cannot hide orphan events or global terminal references.
/// This complete inverse is cold validation, never a new-intake or cleanup role.
pub(in crate::admission_operation_store) fn verify_product_reclamation_inventory(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    use crate::admission_operation_store::knowledge::references::{
        require_retired_reference_owner, ReferenceOwner,
    };
    let mut query = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key>=?1 AND record_key<?2
             UNION SELECT record_key FROM main.admission_operation_recovery_events
             WHERE record_key>=?1 AND record_key<?2
             UNION SELECT projection_key FROM main.authority_global_commits
             WHERE projection_key>=?1 AND projection_key<?2
             ORDER BY 1",
        )
        .map_err(sqlite_error)?;
    let mut rows = query
        .query(params![
            RECLAMATION_PREFIX,
            "product-disposition:reclaimed-proposal-evidence;"
        ])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let retained = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("orphan proposal reclamation terminal"))?;
        let value: ReclaimedProposalEvidence = protected::decode(&retained.payload)?;
        let owner = ProductEvidenceOwner::Proposal {
            scope: value.scope,
            id: value.proposal_id,
            digest: value.proposal_digest,
        };
        let source = product_reclamation_source(tx, &owner)?
            .ok_or_else(|| refused("reclamation inverse has no complete terminal"))?;
        if source.terminal().record_key() != key {
            return Err(refused("proposal reclamation inverse changed its key"));
        }
        // The completed inventory is checked after atomic writer completion.
        // A valid terminal cannot stand in for its genuine retired leaf. The
        // tuple-only adapter remains usable before retirement in that writer.
        let owner = ReferenceOwner::from(source.owner().clone());
        let original = SourceAnchor::capture(source.original());
        let terminal = SourceAnchor::capture(source.terminal());
        for reference in source.references() {
            require_retired_reference_owner(tx, reference, &owner, &original, &terminal)?;
        }
    }
    Ok(())
}
