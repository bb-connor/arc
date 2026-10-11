//! Verify the complete v28 predecessor before enabling mutation journal DDL.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let future: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'security_participant_state_mutations*'
         OR lower(tbl_name) GLOB 'security_participant_state_mutations*')", [], |row| row.get(0)
    ).map_err(sqlite_error)?;
    if future {
        return Err(invariant("pre-v29 native mutation history is unqualified"));
    }
    if on_disk == 28 {
        verify_admission_operation_schema(connection, 28)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::dpop_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::security_participant_migration::verify_all(connection)?;
        super::super::security_participant_state::verify_predecessor(connection)?;
    }
    Ok(())
}
