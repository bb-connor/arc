//! Introduce empty operation-owned v2 DPoP custody without adopting old claims
//! or changing any preceding activation, admission or global-commit digest.
use super::*;

const CLAIM_KINDS: &str = ",\n            'dpop_replay_claim', 'dpop_replay_release'";
const CLAIM_CONTEXT: &str = "\n        OR (mutation_kind IN ('dpop_replay_claim', 'dpop_replay_release')\n            AND recovery_claim_digest IS NOT NULL\n            AND participant_digest IS NOT NULL)";

pub(super) fn predecessor_admission_schema() -> String {
    super::migration_v34::predecessor_schema()
        .replace(CLAIM_KINDS, "")
        .replace(CLAIM_CONTEXT, "")
}

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'dpop_replay_claim_*'
          OR lower(tbl_name) GLOB 'dpop_replay_claim_*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v26 schema contains unqualified DPoP custody",
        ));
    }
    let operations: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'admission_operations')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if operations {
        let attached: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operations, json_each(operation_json, '$.attachments') AS attachment
               WHERE json_type(attachment.value, '$.DpopReplayLedgerDigest') IS NOT NULL)", [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if attached {
            return Err(invariant(
                "pre-v26 operation contains unqualified DPoP custody",
            ));
        }
    }
    if on_disk == 25 {
        verify_admission_operation_schema(connection, 25)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
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
    if sql.is_none_or(|sql| sql.contains(CLAIM_KINDS)) {
        return Ok(());
    }
    tx.execute_batch(
        "DROP TRIGGER admission_operation_commits_exact_lease;
        DROP TRIGGER admission_operation_commits_immutable;
        DROP TRIGGER admission_operation_commits_no_delete;
        DROP INDEX admission_operation_commits_operation;
        ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v25;",
    )
    .map_err(sqlite_error)?;
    tx.execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    tx.execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;
        INSERT INTO admission_operation_commits SELECT * FROM admission_operation_commits_v25 ORDER BY commit_sequence;
        DROP TABLE admission_operation_commits_v25;").map_err(sqlite_error)?;
    tx.execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}
