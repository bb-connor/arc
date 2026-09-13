//! Preserve the exact two-stage migration history while enabling one immutable
//! activation event. No pre-v21 activation is adopted or reconstructed.

use super::*;

#[cfg(test)]
mod tests;

const ACTIVE_KIND: &str = ", 'activate_runtime_replay_source'";
const ACTIVE_TRANSITION: &str =
    "\n        OR (sequence = 3 AND mutation_kind = 'activate_runtime_replay_source')";

pub(super) fn predecessor_schema() -> String {
    RUNTIME_REPLAY_MIGRATION_SCHEMA
        .replace("sequence BETWEEN 1 AND 3", "sequence BETWEEN 1 AND 2")
        .replace(ACTIVE_KIND, "")
        .replace(ACTIVE_TRANSITION, "")
}

pub(super) fn verify_pre_migration_schema(
    connection: &Transaction<'_>,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if on_disk == 20 {
        verify_admission_operation_schema(connection, 20)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
    }
    if table_exists(connection, "runtime_replay_migration_events")? {
        let active: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_replay_migration_events
                WHERE sequence NOT BETWEEN 1 AND 2 OR mutation_kind = 'activate_runtime_replay_source')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if active {
            return Err(invariant(
                "pre-v21 runtime migration contains unqualified activation",
            ));
        }
    }
    Ok(())
}

pub(super) fn migrate_activation_event(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    if !table_exists(transaction, "runtime_replay_migration_events")? {
        return Ok(());
    }
    transaction.execute_batch(
        "DROP TRIGGER runtime_replay_migration_events_no_replace;
         DROP TRIGGER runtime_replay_migration_events_immutable;
         DROP TRIGGER runtime_replay_migration_events_no_delete;
         ALTER TABLE runtime_replay_migration_events RENAME TO runtime_replay_migration_events_v20;"
    ).map_err(sqlite_error)?;
    transaction
        .execute_batch(RUNTIME_REPLAY_MIGRATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction.execute_batch(
        "INSERT INTO runtime_replay_migration_events (
             runtime_authority_id, sequence, mutation_kind, expectation_digest,
             inventory_sha256, event_digest, observed_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
         ) SELECT runtime_authority_id, sequence, mutation_kind, expectation_digest,
                  inventory_sha256, event_digest, observed_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
           FROM runtime_replay_migration_events_v20 ORDER BY runtime_authority_id, sequence;
         DROP TABLE runtime_replay_migration_events_v20;"
    ).map_err(sqlite_error)
}
