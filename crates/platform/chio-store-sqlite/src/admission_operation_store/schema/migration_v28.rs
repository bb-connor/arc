//! Add only an empty native projection. Imported v27 history remains unchanged.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    super::super::security_participant_state::schema::require_absent(connection)?;
    let global_exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND lower(name) = 'authority_global_commits')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if global_exists {
        let references: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'security_participant_state')", [], |row| row.get(0)).map_err(sqlite_error)?;
        if references {
            return Err(invariant(
                "pre-v28 schema contains unqualified native security references",
            ));
        }
    }
    if on_disk == 27 {
        verify_admission_operation_schema(connection, 27)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::dpop_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::security_participant_migration::verify_all(connection)?;
    }
    Ok(())
}
