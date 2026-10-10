//! Retained checkpoints add no new admission identity or rewrite of old bytes.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    super::super::security_participant_state::checkpoint::require_absent(connection)?;
    if table_exists(connection, "authority_global_commits")? {
        let future: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'security_participant_checkpoint')",
            [],|row|row.get(0),
        ).map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "pre-v36 admission has unqualified checkpoint references",
            ));
        }
    }
    if on_disk == 35 && table_exists(connection, "admission_operations")? {
        verify_admission_operation_schema(connection, 35)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::recovery::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}
