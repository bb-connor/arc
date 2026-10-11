//! Canonical status is bound to a participant digest in the anchored commit chain.

use super::*;

const MAX_STATUS_BYTES: usize = 4_096;

pub(super) fn load(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<AdmissionRecoveryStatusV1>, AdmissionOperationStoreError> {
    let row = connection
        .query_row(
            "SELECT canonical_status, status_digest, quarantined, retry_not_before_unix_ms
         FROM admission_operation_recovery_deferrals WHERE operation_id=?1",
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let commit = connection.query_row(
        "SELECT participant_digest, mutation_kind FROM admission_operation_commits
         WHERE operation_id=?1 AND mutation_kind IN ('recovery_deferred','recovery_deferral_cleared')
         ORDER BY commit_sequence DESC LIMIT 1",
        [operation.binding().operation_id().as_str()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .optional().map_err(sqlite_error)?;
    let (row, commit) = match (row, commit) {
        (None, None) => return Ok(None),
        (Some(row), Some(commit)) => (row, commit),
        _ => return Err(invariant("recovery status and committed history disagree")),
    };
    let status: AdmissionRecoveryStatusV1 =
        chio_core::canonical::UntrustedJsonText::from_wire(&row.0, MAX_STATUS_BYTES)
            .and_then(|input| input.decode_canonical())
            .map_err(AdmissionOperationStoreError::from)?;
    status.deferral.validate_for(operation)?;
    let digest = sha256_hex(&row.0);
    let kind = if status.quarantined {
        "recovery_deferred"
    } else {
        "recovery_deferral_cleared"
    };
    if digest != row.1
        || digest != commit.0
        || commit.1 != kind
        || row.2 != status.quarantined
        || stored_u64(row.3, "recovery retry deadline")? != status.deferral.retry_not_before_unix_ms
    {
        return Err(invariant(
            "recovery status does not match its anchored canonical record",
        ));
    }
    Ok(Some(status))
}

pub(super) fn persist(
    transaction: &Transaction<'_>,
    stored: &StoredOperation,
    status: &AdmissionRecoveryStatusV1,
    kind: &'static str,
    owner: &SqliteServingOwner,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let canonical = canonical_json_bytes(status).map_err(|error| invariant(error.to_string()))?;
    if canonical.len() > MAX_STATUS_BYTES {
        return Err(invariant("canonical recovery status exceeded its bound"));
    }
    let digest = sha256_hex(&canonical);
    transaction.execute(
        "INSERT INTO admission_operation_recovery_deferrals
         (operation_id, canonical_status, status_digest, quarantined, retry_not_before_unix_ms)
         VALUES(?1,?2,?3,?4,?5) ON CONFLICT(operation_id) DO UPDATE SET
         canonical_status=excluded.canonical_status, status_digest=excluded.status_digest,
         quarantined=excluded.quarantined, retry_not_before_unix_ms=excluded.retry_not_before_unix_ms",
        params![stored.operation.binding().operation_id().as_str(), canonical, digest,
            status.quarantined, sqlite_i64(status.deferral.retry_not_before_unix_ms, "recovery retry deadline")?])
        .map_err(sqlite_error)?;
    let changed = transaction.execute(
        "UPDATE admission_operations SET updated_at_unix_ms=?1 WHERE operation_id=?2 AND version=?3",
        params![sqlite_i64(now, "recovery status time")?, stored.operation.binding().operation_id().as_str(),
            sqlite_i64(stored.operation.version(), "recovery operation version")?]).map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant(
            "recovery status lost its exact operation snapshot",
        ));
    }
    append_operation_commit_with_participant(
        transaction,
        &stored.operation,
        &encode_operation(&stored.operation)?,
        stored.recovery_claim.as_ref(),
        kind,
        Some(&digest),
        owner,
        now,
    )?;
    Ok(())
}
