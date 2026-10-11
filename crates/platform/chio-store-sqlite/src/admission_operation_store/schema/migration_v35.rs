//! Preserve historical operation and commit bytes while adding recovery status.

use super::*;

const KINDS: &str = ",\n            'recovery_deferred', 'recovery_deferral_cleared'";
const CONTEXT: &str = "\n        OR (mutation_kind = 'recovery_deferred'\n            AND recovery_claim_digest IS NOT NULL\n            AND participant_digest IS NOT NULL)\n        OR (mutation_kind = 'recovery_deferral_cleared'\n            AND participant_digest IS NOT NULL)";

pub(super) fn predecessor_sql(sql: String) -> String {
    sql.replace(KINDS, "").replace(CONTEXT, "")
}

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let future: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name GLOB 'admission_operation_recovery_*'
                       OR tbl_name GLOB 'admission_operation_recovery_*')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if future {
        return Err(invariant(
            "pre-v35 admission contains an unqualified recovery namespace",
        ));
    }
    if on_disk == 34 {
        verify_admission_operation_schema(connection, 34)?;
        verify_admission_operation_data_invariants(connection)?;
    }
    Ok(())
}

pub(super) fn migrate(transaction: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    let sql: Option<String> = transaction.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='admission_operation_commits'",
        [], |row| row.get(0)).optional().map_err(sqlite_error)?;
    if sql.is_none_or(|sql| sql.contains(KINDS)) {
        return Ok(());
    }
    transaction
        .execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
         DROP TRIGGER admission_operation_commits_immutable;
         DROP TRIGGER admission_operation_commits_no_delete;
         DROP INDEX admission_operation_commits_operation;
         ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v34;",
        )
        .map_err(sqlite_error)?;
    create_commit_objects(transaction)?;
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
           FROM admission_operation_commits_v34 ORDER BY commit_sequence;
         DROP TABLE admission_operation_commits_v34;",
        )
        .map_err(sqlite_error)?;
    restore_exact_lease_trigger(transaction)
}

/// Restore only the canonical guard deliberately removed for the history copy.
/// The rebuilt table, index and other guards already exist and remain untouched.
fn restore_exact_lease_trigger(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let compiled = Connection::open_in_memory().map_err(sqlite_error)?;
    compiled
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    let sql: String = compiled
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger'
               AND name = 'admission_operation_commits_exact_lease'
               AND tbl_name = 'admission_operation_commits'",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    transaction.execute_batch(&sql).map_err(sqlite_error)
}

fn create_commit_objects(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let compiled = Connection::open_in_memory().map_err(sqlite_error)?;
    compiled
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    let mut statement = compiled.prepare(
        "SELECT sql FROM sqlite_schema WHERE tbl_name='admission_operation_commits' AND sql IS NOT NULL
         ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name").map_err(sqlite_error)?;
    let objects = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    for sql in objects {
        transaction
            .execute_batch(&sql.map_err(sqlite_error)?)
            .map_err(sqlite_error)?;
    }
    Ok(())
}
