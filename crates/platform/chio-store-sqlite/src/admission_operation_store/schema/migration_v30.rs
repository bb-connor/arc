//! Add only an empty native egress journal after exact predecessor validation.
//! Existing initialization, join records and global chain bytes are untouched.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if super::super::security_participant_state::egress::exists(connection)? {
        return Err(invariant("pre-v30 native egress catalog is unqualified"));
    }
    let has_global: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if has_global {
        let future: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'security_participant_egress')", [], |row| row.get(0)).map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "pre-v30 native egress references are unqualified",
            ));
        }
    }
    if on_disk == 29 {
        verify_admission_operation_schema(connection, 29)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::dpop_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::security_participant_migration::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}
