//! Keyset pages bound physical verification work even when every row is skipped.

use super::*;

const LEGACY_CAPACITY_MESSAGE: &str =
    "legacy recovery selection exceeds the bounded scan; use cursor recovery";

pub(super) fn read(
    store: &SqliteAdmissionOperationStore,
    query: AdmissionRecoveryPageQuery<'_>,
) -> Result<AdmissionRecoveryPageV1, AdmissionOperationStoreError> {
    if query.candidate_limit == 0 || query.candidate_limit > MAX_RECOVERY_BATCH {
        return Err(invariant(
            "recovery candidate limit must be between 1 and 256",
        ));
    }
    let mut connection = store.connection()?;
    let transaction = store.begin_read(&mut connection)?;
    verify_active_owner(&transaction, &store.serving_owner, Some(query.fence))?;
    schema::authority_validation_time(&transaction, query.not_after_unix_ms, &store.serving_owner)?;
    let page = read_snapshot(&transaction, query)?;
    transaction.commit().map_err(sqlite_error)?;
    Ok(page)
}

pub(super) fn read_legacy(
    store: &SqliteAdmissionOperationStore,
    not_after_unix_ms: u64,
    limit: usize,
) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    if limit > MAX_RECOVERY_BATCH {
        return Err(invariant(
            "recovery candidate limit must be between 1 and 256",
        ));
    }
    let mut connection = store.connection()?;
    let transaction = store.begin_read(&mut connection)?;
    let fence = &store.serving_owner.fence;
    verify_active_owner(&transaction, &store.serving_owner, Some(fence))?;
    schema::authority_validation_time(&transaction, not_after_unix_ms, &store.serving_owner)?;
    let mut remaining = MAX_RECOVERY_BATCH;
    let mut cursor = None;
    let mut operations = Vec::with_capacity(limit);
    let mut unresolved_tail = false;
    loop {
        let candidate_limit = (limit - operations.len()).min(remaining);
        let page = read_snapshot(
            &transaction,
            AdmissionRecoveryPageQuery {
                not_after_unix_ms,
                candidate_limit,
                after_operation_id: cursor.as_ref(),
                fence,
            },
        )?;
        remaining = remaining
            .checked_sub(page.scanned_candidates)
            .ok_or_else(|| invariant("legacy recovery candidate budget exceeded"))?;
        operations.extend(page.operations);
        if operations.len() == limit || page.next_cursor.is_none() {
            break;
        }
        cursor = page.next_cursor;
        if remaining == 0 {
            // One primary-key existence probe allocates/decodes no candidate.
            // Absence proves the stream ended; any raw tail remains unresolved.
            let has_tail: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operations WHERE operation_id > ?1 LIMIT 1)",
                [cursor.as_ref().map_or("", AdmissionOperationId::as_str)],
                |row| row.get(0),
            ).map_err(sqlite_error)?;
            if has_tail {
                unresolved_tail = true;
            }
            break;
        }
    }
    store
        .serving_owner
        .verify_authority_anchor(&transaction)
        .map_err(map_owner_error)?;
    transaction.commit().map_err(sqlite_error)?;
    store
        .serving_owner
        .verify_authority_anchor(&connection)
        .map_err(map_owner_error)?;
    if unresolved_tail {
        Err(AdmissionOperationStoreError::Unavailable(
            LEGACY_CAPACITY_MESSAGE.to_owned(),
        ))
    } else {
        Ok(operations)
    }
}

/// Both entry points supply one already fenced and clock-validated snapshot.
/// Selection, exact row validation and validation-before-skip stay shared.
fn read_snapshot(
    transaction: &Transaction<'_>,
    query: AdmissionRecoveryPageQuery<'_>,
) -> Result<AdmissionRecoveryPageV1, AdmissionOperationStoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT operation_id, request_namespace_digest, request_id,
         operation_json, state, terminal, coordinator_lease_epoch,
         version, created_at_unix_ms, updated_at_unix_ms,
         recovery_claimant_id, recovery_coordinator_lease_id,
         recovery_coordinator_lease_epoch, recovery_claimed_version,
         recovery_expires_at_unix_ms, recovery_store_uuid,
         recovery_store_lease_id, recovery_store_owner_epoch
         FROM admission_operations o WHERE operation_id > ?1
           AND created_at_unix_ms <= ?2
           AND (terminal=0 OR EXISTS(SELECT 1 FROM admission_operation_recovery_deferrals d
                                    WHERE d.operation_id=o.operation_id AND d.quarantined=1))
           AND (recovery_expires_at_unix_ms IS NULL OR recovery_expires_at_unix_ms <= ?2
                OR recovery_store_uuid <> ?3 OR recovery_store_lease_id <> ?4
                OR recovery_store_owner_epoch <> ?5 OR terminal=1)
         ORDER BY operation_id LIMIT ?6",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            query.after_operation_id.map_or("", |id| id.as_str()),
            sqlite_i64(query.not_after_unix_ms, "recovery page time")?,
            &query.fence.store_uuid,
            &query.fence.lease_id,
            sqlite_i64(query.fence.owner_epoch, "recovery owner epoch")?,
            i64::try_from(query.candidate_limit)
                .map_err(|_| invariant("recovery page limit overflow"))?
        ])
        .map_err(sqlite_error)?;
    let mut operations = Vec::new();
    let mut scanned_candidates = 0_usize;
    let mut last = None;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        scanned_candidates = scanned_candidates
            .checked_add(1)
            .ok_or_else(|| invariant("recovery page count overflow"))?;
        let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
        last = Some(stored.operation.binding().operation_id().clone());
        verify_latest_commit(transaction, &stored)?;
        caller_dispatch_context::load(transaction, &stored.operation)?;
        runtime_participant::verify_operation(transaction, &stored.operation)?;
        governed_approval_claim::verify_stored_operation(transaction, &stored.operation)?;
        dpop_claim::verify_stored_operation(transaction, &stored.operation)?;
        let recovery = status::load(transaction, &stored.operation)?;
        if recovery.as_ref().is_some_and(|status| {
            status.quarantined && status.deferral.retry_not_before_unix_ms > query.not_after_unix_ms
        }) {
            continue;
        }
        if stored.operation.state() == AdmissionOperationState::ApprovalRequired
            && stored
                .operation
                .parked_approval_deadline_unix_ms()?
                .is_none_or(|deadline| deadline > query.not_after_unix_ms)
        {
            continue;
        }
        if stored.operation.state() == AdmissionOperationState::AwaitingCallerReport
            && !recovery.as_ref().is_some_and(|status| status.quarantined)
        {
            continue;
        }
        if super::super::store::waits_for_live_nonce(
            transaction,
            &stored.operation,
            query.not_after_unix_ms,
        )? {
            continue;
        }
        operations.push(stored.operation);
    }
    drop(rows);
    drop(statement);
    Ok(AdmissionRecoveryPageV1 {
        operations,
        scanned_candidates,
        next_cursor: if scanned_candidates == query.candidate_limit {
            last
        } else {
            None
        },
    })
}
