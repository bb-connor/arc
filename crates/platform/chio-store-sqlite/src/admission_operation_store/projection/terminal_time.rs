//! Sealed apply time and later authenticated status event time remain distinct.
use super::*;
use crate::admission_operation_store::history_scope::TerminalCasBinding;

pub(super) fn verify(
    connection: &Connection,
    stored: &StoredOperation,
    projection: &StoredTerminalProjection,
    history: &CheckedHistoryScope<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    history.require_connection(connection)?;
    verify_outcome_recovery_status(connection, &stored.operation)?;
    let committed = stored_u64(
        projection.committed_at_unix_ms,
        "projection_committed_at_unix_ms",
    )?;
    validate_trusted_time(committed, "projection_committed_at_unix_ms")?;
    let operation_digest = sha256_hex(&encode_operation(&stored.operation)?);
    let claim_digest = stored
        .recovery_claim
        .as_ref()
        .map(recovery_claim_digest)
        .transpose()?;
    let fence = StoreMutationFence {
        store_uuid: projection.store_uuid.clone(),
        lease_id: projection.store_lease_id.clone(),
        owner_epoch: stored_u64(projection.store_owner_epoch, "projection_store_owner_epoch")?,
    };
    let expected = TerminalCasBinding {
        operation_id: stored.operation.binding().operation_id().as_str(),
        operation_version: stored.operation.version(),
        operation_digest: &operation_digest,
        recovery_claim_digest: claim_digest.as_deref(),
        fence: &fence,
        recorded_at_unix_ms: committed,
    };
    // Exact historical uniqueness and apply time require the checked complete
    // history. Reuse this scope across the transaction's other terminal reads.
    history.qualify(connection)?;
    let mut statement = connection
        .prepare(
            "SELECT operation_digest,recovery_claim_digest,participant_digest,store_uuid,
                store_lease_id,store_owner_epoch,recorded_at_unix_ms
         FROM admission_operation_commits WHERE operation_id=?1 AND operation_version=?2
           AND mutation_kind='compare_and_swap' ORDER BY commit_sequence LIMIT 2",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            expected.operation_id,
            sqlite_i64(expected.operation_version, "terminal_operation_version")?
        ])
        .map_err(sqlite_error)?;
    let row = rows.next().map_err(sqlite_error)?.ok_or_else(|| {
        invariant("terminal projection lacks one exact authenticated admission CAS")
    })?;
    let exact = row.get::<_, String>(0).map_err(sqlite_error)? == expected.operation_digest
        && row
            .get::<_, Option<String>>(1)
            .map_err(sqlite_error)?
            .as_deref()
            == expected.recovery_claim_digest
        && row
            .get::<_, Option<String>>(2)
            .map_err(sqlite_error)?
            .is_none()
        && row.get::<_, String>(3).map_err(sqlite_error)? == expected.fence.store_uuid
        && row.get::<_, String>(4).map_err(sqlite_error)? == expected.fence.lease_id
        && stored_u64(
            row.get(5).map_err(sqlite_error)?,
            "terminal_CAS_owner_epoch",
        )? == expected.fence.owner_epoch
        && stored_u64(
            row.get(6).map_err(sqlite_error)?,
            "terminal_CAS_recorded_at",
        )? == expected.recorded_at_unix_ms;
    if !exact || rows.next().map_err(sqlite_error)?.is_some() {
        return Err(invariant(
            "terminal projection lacks one exact authenticated admission CAS",
        ));
    }
    history.require_connection(connection)?;
    Ok(())
}
