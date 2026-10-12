//! Funded caller shares gain a parent index derived from retained requests.
//! No stored operation, request or commit bytes are rewritten.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let future: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                 WHERE name GLOB 'admission_operation_caller_shares*'
                    OR tbl_name GLOB 'admission_operation_caller_shares*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if future {
        return Err(invariant(
            "pre-v37 admission contains an unqualified caller-share index",
        ));
    }
    if on_disk == 36 && table_exists(connection, "admission_operations")? {
        verify_admission_operation_schema(connection, 36)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::recovery::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}

pub(super) fn migrate(transaction: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(super::super::caller_budget::SCHEMA)
        .map_err(sqlite_error)?;
    super::super::caller_budget::backfill(transaction)
}
