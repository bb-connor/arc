//! Bounded family admission followed by authenticated fixture history writes.
use super::*;

/// Precheck the complete bounded knowledge-family allocation, then retain each
/// real authenticated record/event/global commit through the normal writer.
/// The current namespace ceiling is tested by a subsequent exact owning save.
pub(in crate::admission_operation_store) fn fill_intake_events(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    selected: &RecoveryScopeV1,
    target: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if target > 57344 || selected.authority_domain.as_str() != fence.store_uuid {
        return Err(invariant("recovery quota fixture events refused"));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    command_quota_test_support::install_fixture_observed_time_index(&tx)?;
    let (events, bytes): (i64, i64) = tx.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-*'),
            (SELECT coalesce(sum(length(payload)),0) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-*')",
        [], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(sqlite_error)?;
    let current = stored_u64(events, "fixture event count")?;
    let bytes = stored_u64(bytes, "fixture retained bytes")?;
    let scope = scope_key(selected)?;
    let key = format!("knowledge-pin:{scope}:quota-event-reserve");
    if raw(&tx, &key)?.is_some() || current > target {
        return Err(invariant("recovery quota fixture events already retained"));
    }
    if current < target {
        let last = SafeInteger::new(target - 1).map_err(|_| invariant("fixture event refused"))?;
        let largest = encode(&last)?.len() as u64;
        if bytes
            .checked_add(largest)
            .is_none_or(|total| total > 48 * 1024 * 1024)
        {
            return Err(invariant("recovery quota fixture bytes exhausted"));
        }
    }
    // Canonical nonnegative SafeInteger payload length is monotone, every
    // event updates this one initially absent fixed namespace key, and target
    // is <=57,344. The complete family byte/event ceilings were checked above.
    for event in current..target {
        persist_record(
            &tx,
            &store.serving_owner,
            &key,
            &scope,
            "command",
            &encode(&SafeInteger::new(event).map_err(|_| invariant("fixture event refused"))?)?,
            None,
        )?;
    }
    command_quota_test_support::restore_fixture_canonical_schema(&tx)?;
    crate::serving_owner::verify_authenticated_recovery_history(&tx).map_err(map_owner_error)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)
}
