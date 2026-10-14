//! Closed native influence custody: verified native proofs only, intake band.
use super::*;
use crate::admission_operation_store::security_participant_state::{
    VerifiedImportedInfluenceRoot, VerifiedNativeInfluenceHeads,
};

pub(in crate::admission_operation_store) fn persist_native_influence_heads<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    heads: &VerifiedNativeInfluenceHeads<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    heads.verify(tx)?;
    super::super::resources::check_intake_committing(tx)?;
    for write in heads.writes() {
        persist_record(
            tx,
            owner,
            write.key(),
            write.scope(),
            "command",
            write.payload(),
            None,
        )?;
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn persist_imported_influence_root<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    root: &VerifiedImportedInfluenceRoot<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    root.verify(tx)?;
    super::super::resources::check_intake_committing(tx)?;
    persist_record(
        tx,
        owner,
        root.key(),
        root.scope(),
        "command",
        root.payload(),
        None,
    )
}
