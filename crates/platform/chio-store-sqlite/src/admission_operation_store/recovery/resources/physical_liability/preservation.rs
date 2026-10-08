//! An amount check preserves debt but never authenticates its owning borrower.
use super::*;

pub(in crate::admission_operation_store) fn require_intake_preserving_liability(
    tx: &Connection,
    retained: &PhysicalLiabilityData,
    newly_owed: &PhysicalLiabilityData,
    current_write: &PhysicalLiabilityData,
) -> Result<(), AdmissionOperationStoreError> {
    let owed = retained.checked_add(newly_owed)?;
    require_preserved(tx, &owed, current_write, true)
}

pub(in crate::admission_operation_store) fn require_progress_preserving_liability(
    tx: &Connection,
    other_owed: &PhysicalLiabilityData,
    current_write: &PhysicalLiabilityData,
) -> Result<(), AdmissionOperationStoreError> {
    require_preserved(tx, other_owed, current_write, false)
}

fn require_preserved(
    tx: &Connection,
    owed: &PhysicalLiabilityData,
    current: &PhysicalLiabilityData,
    intake: bool,
) -> Result<(), AdmissionOperationStoreError> {
    pricing::verify_profile(tx)?;
    pricing::verify_command_catalog(tx)?;
    let total = owed.checked_add(current)?;
    let usage = physical_usage(tx, false)?;
    let with_current = usage
        .wal
        .checked_add(current.wal_bytes)
        .ok_or_else(|| invariant("physical current WAL liability exhausted"))?;
    let future_wal = usage
        .wal
        .checked_add(total.wal_bytes)
        .ok_or_else(|| invariant("physical retained WAL liability exhausted"))?;
    let floor: u64 = if intake { 128 * MIB } else { 16 * MIB };
    let required_disk = floor
        .checked_add(total.disk_bytes)
        .ok_or_else(|| invariant("physical retained disk liability exhausted"))?;
    if (intake && with_current >= 64 * MIB)
        || future_wal >= 128 * MIB
        || usage.available < required_disk
    {
        return Err(invariant(
            "physical write would consume an owed finishing reserve",
        ));
    }
    let recovery: i64 = tx
        .query_row(
            "SELECT coalesce(max(sequence),0) FROM main.admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let global: i64 = tx
        .query_row(
            "SELECT head_sequence FROM main.authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    for (head, future) in [
        (
            stored_u64(recovery, "physical recovery head")?,
            total.recovery_appends,
        ),
        (
            stored_u64(global, "physical global head")?,
            total.global_appends,
        ),
    ] {
        head.checked_add(future)
            .filter(|sequence| *sequence <= MAX_TRUSTED_UNIX_MS)
            .ok_or_else(|| invariant("physical write would consume an owed history sequence"))?;
    }
    Ok(())
}
