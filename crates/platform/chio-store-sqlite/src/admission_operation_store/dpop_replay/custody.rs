//! Activation and clock checks shared by operation-owned replay mutations.
//! No source callback or recursive operation/anchor load occurs here.
use super::*;

pub(in crate::admission_operation_store) fn require_active_authority(
    connection: &Connection,
    expected: &DpopReplayAuthorityV1,
) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
    let record = super::integrity::verified_projection_records(connection)
        .map_err(map_owner_error)?
        .into_iter()
        .find(|record| record.snapshot.dpop_authority_id() == expected.dpop_authority_id().as_str())
        .ok_or_else(|| invariant("DPoP claim authority is absent"))?;
    if !record.is_active() || record.authority() != Some(expected) {
        return Err(invariant("DPoP claim requires the exact activated domain"));
    }
    Ok(record)
}

pub(in crate::admission_operation_store) fn verify_source_clock_floor(
    record: &DpopReplayMigrationRecordV1,
    observed: u64,
) -> Result<(), AdmissionOperationStoreError> {
    record
        .snapshot
        .validate_transition_time(observed)
        .map_err(integrity_error)?;
    if !record.is_active()
        || record
            .events
            .last()
            .is_none_or(|event| observed < event.observed_at_unix_ms)
    {
        return Err(invariant("DPoP custody observation precedes activation"));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn dpop_clock_tx(
    tx: &Transaction<'_>,
    record: &DpopReplayMigrationRecordV1,
    trusted_now_unix_ms: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = migration_time(tx, trusted_now_unix_ms)?;
    verify_source_clock_floor(record, observed)?;
    Ok(observed)
}
