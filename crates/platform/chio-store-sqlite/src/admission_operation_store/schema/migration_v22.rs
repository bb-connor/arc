//! Introduce only an empty governed approval migration namespace. Existing
//! v21 admission, runtime and replay history must remain exact and verifiable.

use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
         WHERE lower(name) GLOB 'governed_approval_replay_*'
            OR lower(tbl_name) GLOB 'governed_approval_replay_*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if exists {
        return Err(invariant(
            "pre-v22 admission schema contains an unqualified approval replay namespace",
        ));
    }
    if on_disk == 21 {
        verify_admission_operation_schema(connection, 21)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
    }
    Ok(())
}
