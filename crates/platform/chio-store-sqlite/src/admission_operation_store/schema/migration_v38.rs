//! The durable stop chain gains its append-only record and note tables.
//! No existing row is rewritten.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if super::super::stop_epoch::present(connection)?
        || table_exists(connection, "admission_operation_stop_notes")?
    {
        return Err(invariant(
            "pre-v38 admission contains an unqualified stop chain",
        ));
    }
    if on_disk == 37 && table_exists(connection, "admission_operations")? {
        verify_admission_operation_schema(connection, 37)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::recovery::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}

pub(super) fn migrate(transaction: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(super::super::stop_epoch::SCHEMA)
        .map_err(sqlite_error)
}
