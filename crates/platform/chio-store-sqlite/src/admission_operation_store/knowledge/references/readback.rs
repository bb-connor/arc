//! Completion readbacks authenticate exact current custody and original sources.
use super::*;

pub(in crate::admission_operation_store) fn require_active_reference_owner(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    owner: &ReferenceOwner,
    expected_original: &SourceAnchor,
) -> Result<(), AdmissionOperationStoreError> {
    expected_original.verify_historical_identity(tx)?;
    let state = load_reference_state(tx, reference)?;
    let leaf = load_owner_leaf(tx, reference, owner, &state)?
        .ok_or_else(|| refused("reference completion lacks its original owner"))?;
    if leaf.value.state != ReferenceOwnerState::Active || leaf.value.original != *expected_original
    {
        return Err(refused("reference completion changed its original custody"));
    }
    Ok(())
}

/// The closed affine Product retirement proof uses this observer before each
/// mutation. Already spent leaves must name exactly the same terminal; an
/// unrelated authenticated historical row cannot substitute for it.
pub(in crate::admission_operation_store::knowledge) fn require_product_retirement_custody(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    owner: &ReferenceOwner,
    expected_original: &SourceAnchor,
    expected_terminal: &SourceAnchor,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(owner, ReferenceOwner::ProductProposal { .. }) {
        return Err(refused("Product retirement custody selected another owner"));
    }
    expected_original.verify_historical_identity(tx)?;
    expected_terminal.verify_historical_identity(tx)?;
    let state = load_reference_state(tx, reference)?;
    let leaf = load_owner_leaf(tx, reference, owner, &state)?
        .ok_or_else(|| refused("Product retirement lost its original owner"))?;
    if leaf.value.original != *expected_original
        || (leaf.value.state == ReferenceOwnerState::Retired
            && leaf.value.retirement.as_ref() != Some(expected_terminal))
    {
        return Err(refused(
            "Product retirement rebound its original or terminal owner",
        ));
    }
    Ok(())
}

/// Retained Product replay must name the actual independently authenticated
/// irreversible terminal, including its complete original scoped owner.
/// This observer grants no byte release, intake or reference mutation.
pub(in crate::admission_operation_store) fn require_retired_reference_owner(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    owner: &ReferenceOwner,
    expected_original: &SourceAnchor,
    expected_terminal: &SourceAnchor,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(owner, ReferenceOwner::ProductProposal { .. }) {
        return Err(refused(
            "retained Product replay selected another owner purpose",
        ));
    }
    expected_original.verify_historical_identity(tx)?;
    expected_terminal.verify_historical_identity(tx)?;
    let state = load_reference_state(tx, reference)?;
    let leaf = load_owner_leaf(tx, reference, owner, &state)?
        .ok_or_else(|| refused("retired reference replay lacks its original owner"))?;
    if leaf.value.state != ReferenceOwnerState::Retired
        || leaf.value.original != *expected_original
        || leaf.value.retirement.as_ref() != Some(expected_terminal)
    {
        return Err(refused(
            "retired reference replay changed its exact terminal custody",
        ));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn require_new_artifact_reference_baseline(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    expected_metadata_commit: &SourceAnchor,
) -> Result<(), AdmissionOperationStoreError> {
    expected_metadata_commit.verify_historical_identity(tx)?;
    let state = load_reference_state(tx, reference)?;
    let ReferenceBaselineSource::NewArtifact { source } = &state.aggregate.value.baseline.source
    else {
        return Err(refused(
            "new artifact completion lacks its exact metadata baseline",
        ));
    };
    if source != expected_metadata_commit {
        return Err(refused(
            "new artifact completion changed its metadata commitment",
        ));
    }
    Ok(())
}
