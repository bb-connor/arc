//! The recovery runtime installs its records, events, command aliases,
//! captured terminal custody and knowledge encoding catalogs in one step.
use super::*;

const ORIGIN_PRESENCE_SQL: &str = include_str!("../../recovery_origin_presence.sql");
const COMMAND_ALIAS_SQL: &str = include_str!("../../recovery_command_alias.sql");
const CAPTURED_TERMINAL_SQL: &str = include_str!("../../recovery_captured_terminal.sql");
const KNOWLEDGE_ENCODING_SQL: &str = include_str!("../../recovery_knowledge_encoding_atoms.sql");
const REFERENCE_CAPACITY_SQL: &str = include_str!("../../recovery_reference_capacity.sql");
const CHUNK_ACCOUNTING_SQL: &str =
    include_str!("../../recovery_knowledge_journal_chunk_accounting.sql");

/// The complete recovery runtime catalog, in installation order.
pub(super) fn sql() -> [&'static str; 9] {
    [
        super::super::recovery_runtime::SQL,
        super::super::recovery_runtime::deployment_history::SQL,
        super::super::recovery_runtime::historical_holds::SQL,
        ORIGIN_PRESENCE_SQL,
        COMMAND_ALIAS_SQL,
        CAPTURED_TERMINAL_SQL,
        KNOWLEDGE_ENCODING_SQL,
        REFERENCE_CAPACITY_SQL,
        CHUNK_ACCOUNTING_SQL,
    ]
}

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if table_exists(connection, "authority_global_commits")? {
        let future: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'recovery')",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "pre-v38 admission has unqualified recovery runtime references",
            ));
        }
    }
    if on_disk == 37 && table_exists(connection, "admission_operations")? {
        verify_admission_operation_schema(connection, 37)?;
        verify_operation_data(connection, CallerShareIndex::Current)?;
        super::super::caller_budget::verify_ownership(connection)?;
        super::super::recovery::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}

pub(super) fn migrate(transaction: &Connection) -> Result<(), AdmissionOperationStoreError> {
    sql().into_iter().try_for_each(|sql| {
        transaction
            .execute_batch(sql)
            .map_err(sqlite_error)
    })
}
