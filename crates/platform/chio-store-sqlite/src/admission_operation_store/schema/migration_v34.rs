//! A new nonterminal caller-report wait state. Existing terminal records and
//! every historical JSON byte, commit digest and fence remain unchanged.
use super::*;

#[cfg(test)]
mod tests;

pub(super) fn predecessor_schema() -> String {
    ADMISSION_OPERATION_SCHEMA.replace("'awaiting_caller_report', ", "")
}

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if !table_exists(connection, "admission_operations")? {
        return Ok(());
    }
    let future: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operations WHERE state = 'awaiting_caller_report'
         OR json_extract(operation_json, '$.state') = 'awaiting_caller_report')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if future {
        return Err(invariant(
            "pre-v34 admission contains unqualified caller wait state",
        ));
    }
    if on_disk == 33 {
        verify_admission_operation_schema(connection, 33)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::dpop_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::security_participant_migration::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}

pub(super) fn migrate(
    tx: &Transaction<'_>,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let sql: Option<String> = tx
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'admission_operations'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if sql.is_none_or(|sql| sql.contains("'awaiting_caller_report'")) {
        return Ok(());
    }
    // The caller disables FK renaming and checks every FK before commit. Only
    // canonical, verified table-owned objects are removed during the rebuild.
    // Request-id lookup was added in v11. Its absence is legitimate only for
    // earlier predecessors; never repair a missing required current index.
    tx.execute_batch(if on_disk < 11 {
        "DROP INDEX IF EXISTS admission_operations_request_id;"
    } else {
        "DROP INDEX admission_operations_request_id;"
    })
    .map_err(sqlite_error)?;
    tx.execute_batch(
        "DROP INDEX admission_operations_replay_key;
         DROP INDEX admission_operations_recovery;
         DROP TRIGGER admission_operations_immutable_identity;
         DROP TRIGGER admission_operations_versioned_body;
         DROP TRIGGER admission_operations_terminal_immutable;
         DROP TRIGGER admission_operations_no_delete;
         DROP TRIGGER admission_operations_terminal_no_claim;
         DROP TRIGGER admission_operations_commit_threshold_approval;
         DROP TRIGGER admission_operations_cancel_threshold_approval;
         ALTER TABLE admission_operations RENAME TO admission_operations_v33;",
    )
    .map_err(sqlite_error)?;
    create_parent_objects(tx)?;
    tx.execute_batch(
        "INSERT INTO admission_operations (
            operation_id, request_namespace_digest, request_id, operation_json,
            state, terminal, coordinator_lease_epoch, version, created_at_unix_ms, updated_at_unix_ms,
            recovery_claimant_id, recovery_coordinator_lease_id, recovery_coordinator_lease_epoch,
            recovery_claimed_version, recovery_expires_at_unix_ms, recovery_store_uuid,
            recovery_store_lease_id, recovery_store_owner_epoch
         ) SELECT operation_id, request_namespace_digest, request_id, operation_json,
            state, terminal, coordinator_lease_epoch, version, created_at_unix_ms, updated_at_unix_ms,
            recovery_claimant_id, recovery_coordinator_lease_id, recovery_coordinator_lease_epoch,
            recovery_claimed_version, recovery_expires_at_unix_ms, recovery_store_uuid,
            recovery_store_lease_id, recovery_store_owner_epoch FROM admission_operations_v33;
         DROP TABLE admission_operations_v33;",
    ).map_err(sqlite_error)
}

/// Rebuild only the owned parent objects. Executing the complete current
/// schema here would silently repair missing child triggers before the older
/// migrations can reject them, weakening predecessor-catalog validation.
fn create_parent_objects(tx: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    let compiled = Connection::open_in_memory().map_err(sqlite_error)?;
    compiled
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    let mut statement = compiled
        .prepare(
            "SELECT sql FROM sqlite_schema
         WHERE tbl_name = 'admission_operations' AND sql IS NOT NULL
           AND type IN ('table', 'index', 'trigger')
         ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name",
        )
        .map_err(sqlite_error)?;
    let objects = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    for sql in objects {
        tx.execute_batch(&sql.map_err(sqlite_error)?)
            .map_err(sqlite_error)?;
    }
    Ok(())
}
