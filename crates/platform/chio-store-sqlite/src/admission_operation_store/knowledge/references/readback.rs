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
