//! Introduce an empty DPoP migration namespace without adopting prior data.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'dpop_replay_*'
         OR lower(tbl_name) GLOB 'dpop_replay_*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v24 schema contains an unqualified DPoP replay namespace",
        ));
    }
    if on_disk == 23 {
        verify_admission_operation_schema(connection, 23)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
    }
    Ok(())
}
