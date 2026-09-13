//! Preserve v22 history while introducing operation-owned approval claims and
//! one irreversible activation event. Never adopt preexisting claim authority.
use super::*;

const CLAIM_KINDS: &str = ",\n            'governed_approval_claim', 'governed_approval_release'";
const CLAIM_CONTEXT: &str = "\n        OR (mutation_kind IN ('governed_approval_claim', 'governed_approval_release')\n            AND recovery_claim_digest IS NOT NULL\n            AND participant_digest IS NOT NULL)";

pub(super) fn predecessor_admission_schema() -> String {
    super::migration_v26::predecessor_admission_schema()
        .replace(CLAIM_KINDS, "")
        .replace(CLAIM_CONTEXT, "")
}
pub(super) fn predecessor_approval_schema() -> String {
    GOVERNED_APPROVAL_REPLAY_MIGRATION_SCHEMA
        .replace("sequence BETWEEN 1 AND 3", "sequence BETWEEN 1 AND 2")
        .replace(", 'activate_governed_approval_replay_source'", "")
        .replace("\n        OR (sequence = 3 AND mutation_kind = 'activate_governed_approval_replay_source')", "")
}
pub(super) fn verify_pre_migration_schema(
    tx: &Transaction<'_>,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'governed_approval_replay_claim_*'
          OR lower(tbl_name) GLOB 'governed_approval_replay_claim_*')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v23 schema contains unqualified approval claims",
        ));
    }
    if on_disk == 22 {
        verify_admission_operation_schema(tx, 22)?;
        verify_admission_operation_data_invariants(tx)?;
        super::super::runtime_participant::verify_all(tx)?;
        super::super::governed_approval_replay::verify_all_records(tx).map_err(invariant)?;
    }
    if table_exists(tx, "governed_approval_replay_migration_events")? {
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM governed_approval_replay_migration_events WHERE sequence NOT BETWEEN 1 AND 2)", [],
            |row| row.get(0)).map_err(sqlite_error)?;
        if active {
            return Err(invariant("pre-v23 approval activation is unqualified"));
        }
    }
    Ok(())
}
pub(super) fn migrate(tx: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    let sql: Option<String> = tx
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'admission_operation_commits'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if sql.is_some_and(|sql| !sql.contains(CLAIM_KINDS)) {
        tx.execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v22;",
        )
        .map_err(sqlite_error)?;
        tx.execute_batch(ADMISSION_OPERATION_SCHEMA)
            .map_err(sqlite_error)?;
        tx.execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;
            INSERT INTO admission_operation_commits SELECT * FROM admission_operation_commits_v22 ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v22;").map_err(sqlite_error)?;
        tx.execute_batch(ADMISSION_OPERATION_SCHEMA)
            .map_err(sqlite_error)?;
    }
    if table_exists(tx, "governed_approval_replay_migration_events")? {
        tx.execute_batch("DROP TRIGGER governed_approval_replay_migration_events_no_replace;
            DROP TRIGGER governed_approval_replay_migration_events_immutable;
            DROP TRIGGER governed_approval_replay_migration_events_no_delete;
            ALTER TABLE governed_approval_replay_migration_events RENAME TO governed_approval_replay_migration_events_v22;").map_err(sqlite_error)?;
        tx.execute_batch(GOVERNED_APPROVAL_REPLAY_MIGRATION_SCHEMA)
            .map_err(sqlite_error)?;
        tx.execute_batch("INSERT INTO governed_approval_replay_migration_events
            SELECT * FROM governed_approval_replay_migration_events_v22 ORDER BY approval_authority_id, sequence;
            DROP TABLE governed_approval_replay_migration_events_v22;").map_err(sqlite_error)?;
    }
    Ok(())
}
