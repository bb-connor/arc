//! Add only empty, explicit v2 activation state. Preserve v24 import digests.
use super::*;

pub(super) fn predecessor_schema() -> String {
    DPOP_REPLAY_MIGRATION_SCHEMA
        .replace("sequence BETWEEN 1 AND 3", "sequence BETWEEN 1 AND 2")
        .replace(", 'activate_dpop_replay_source'", "")
        .replace(
            "\n        OR (sequence = 3 AND mutation_kind = 'activate_dpop_replay_source')",
            "",
        )
}

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'dpop_replay_authority_*' OR lower(tbl_name) GLOB 'dpop_replay_authority_*')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v25 schema contains unqualified DPoP activation",
        ));
    }
    if on_disk == 24 {
        verify_admission_operation_schema(connection, 24)?;
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

pub(super) fn migrate(transaction: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    if !table_exists(transaction, "dpop_replay_migration_events")? {
        return Ok(());
    }
    transaction
        .execute_batch(
            "DROP TRIGGER dpop_replay_migration_events_no_replace;
        DROP TRIGGER dpop_replay_migration_events_immutable;
        DROP TRIGGER dpop_replay_migration_events_no_delete;
        ALTER TABLE dpop_replay_migration_events RENAME TO dpop_events_v24_migration;",
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(DPOP_REPLAY_MIGRATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction.execute_batch("INSERT INTO dpop_replay_migration_events SELECT * FROM dpop_events_v24_migration ORDER BY dpop_authority_id, sequence;
        DROP TABLE dpop_events_v24_migration;").map_err(sqlite_error)?;
    Ok(())
}
