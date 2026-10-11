//! Extend participant commit kinds without rewriting historical digests, fences,
//! sequence numbers or authority-observed times. No claim history is adopted.

use super::*;

#[cfg(test)]
mod tests;

const CLAIM_KINDS: &str =
    ",\n            'runtime_participant_claim', 'runtime_participant_release'";
const CLAIM_CONTEXT: &str = "\n        OR (mutation_kind IN ('runtime_participant_claim', 'runtime_participant_release')\n            AND recovery_claim_digest IS NOT NULL\n            AND participant_digest IS NOT NULL)";

/// The only admission DDL changes in v20 are these two commit constraints.
/// Runtime tables are separate schemas and must not exist in a predecessor.
pub(super) fn predecessor_schema() -> String {
    super::migration_v23::predecessor_admission_schema()
        .replace(CLAIM_KINDS, "")
        .replace(CLAIM_CONTEXT, "")
}

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE lower(name) GLOB 'runtime_replay_claim_*'
                OR lower(tbl_name) GLOB 'runtime_replay_claim_*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v20 admission schema contains an unqualified runtime claim namespace",
        ));
    }
    if on_disk == 19 {
        verify_admission_operation_schema(connection, 19)?;
        verify_admission_operation_data_invariants(connection)?;
    }
    Ok(())
}

pub(super) fn migrate_commit_kinds(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let current_sql: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'admission_operation_commits'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    // An earlier migration can already have rebuilt this table with current
    // DDL. Final canonical verification still rejects any noncanonical shape.
    if current_sql.is_none_or(|sql| sql.contains(CLAIM_KINDS)) {
        return Ok(());
    }
    transaction
        .execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
         DROP TRIGGER admission_operation_commits_immutable;
         DROP TRIGGER admission_operation_commits_no_delete;
         DROP INDEX admission_operation_commits_operation;
         ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v19;",
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(&migration_v23::predecessor_admission_schema())
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
         INSERT INTO admission_operation_commits (
             commit_sequence, operation_id, operation_version, mutation_kind,
             operation_digest, recovery_claim_digest, participant_digest,
             previous_chain_digest, chain_digest, store_uuid, store_lease_id,
             store_owner_epoch, recorded_at_unix_ms, observed_at_unix_ms
         ) SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                  operation_digest, recovery_claim_digest, participant_digest,
                  previous_chain_digest, chain_digest, store_uuid, store_lease_id,
                  store_owner_epoch, recorded_at_unix_ms, observed_at_unix_ms
           FROM admission_operation_commits_v19 ORDER BY commit_sequence;
         DROP TABLE admission_operation_commits_v19;",
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(&migration_v23::predecessor_admission_schema())
        .map_err(sqlite_error)
}
