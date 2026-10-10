//! Original observation spacing derives from its exact protected workflow head.
use super::*;

const MINIMUM_LOOKUP_INTERVAL_MS: u64 = 1000;

pub(super) fn require_spacing(
    tx: &Transaction<'_>,
    record: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let head = source_reference(tx, &key)?;
    let current = raw_checked(tx, &key)?.ok_or(AdmissionOperationStoreError::NotFound)?;
    if head.scope_key() != scope_key(&record.scope)?
        || head.kind() != "workflow"
        || head.version() != record.revision.get()
        || current.payload != encode(record)?
    {
        return Err(invariant("recovery provider clock changed its workflow"));
    }
    // source_reference authenticates the latest exact event and its unique
    // global commitment. This indexed lookup reads that same event's clock.
    let observed: i64 = tx
        .query_row(
            "SELECT observed_at FROM admission_operation_recovery_events
             WHERE sequence=?1 AND record_key=?2 AND record_version=?3",
            params![
                sqlite_i64(head.event_sequence(), "provider clock event sequence")?,
                &key,
                sqlite_i64(head.version(), "provider clock workflow version")?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let observed = stored_u64(observed, "provider clock observed time")?;
    let elapsed = now
        .checked_sub(observed)
        .ok_or_else(|| invariant("recovery provider observation clock regressed"))?;
    if record.provider_lookups.get() != 0 && elapsed < MINIMUM_LOOKUP_INTERVAL_MS {
        return Err(invariant("recovery provider observation is not yet spaced"));
    }
    // A successful lookup appends its next workflow head in this same writer.
    // Later lawful workflow writes only move this conservative clock forward.
    Ok(())
}
