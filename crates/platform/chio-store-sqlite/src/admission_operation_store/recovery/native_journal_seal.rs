//! One native journal seal, admitted under the band of the append it precedes.
//!
//! The sealing native writer mints the proof from its own verified segment in
//! this transaction. A seal before a pre-effect append takes the physical
//! intake band. A seal before an owed post-effect append takes the settlement
//! band only with the allowance its plan priced before the effect; the proof
//! authenticates that allowance. The seal is outside every generic pool.
use super::*;
use crate::admission_operation_store::security_participant_state::{
    NativeSealAdmission, VerifiedNativeJournalSeal,
};

pub(in crate::admission_operation_store) fn persist_native_journal_seal<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    seal: &VerifiedNativeJournalSeal<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    seal.verify(tx)?;
    match seal.admission() {
        NativeSealAdmission::Intake => super::super::resources::check_intake_committing(tx)?,
        NativeSealAdmission::Owed => super::super::resources::check_committing(tx)?,
    }
    persist_record(
        tx,
        owner,
        seal.key(),
        seal.scope(),
        "command",
        seal.payload(),
        None,
    )
}
