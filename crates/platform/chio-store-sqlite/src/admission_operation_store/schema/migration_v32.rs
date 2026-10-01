//! Add an empty output journal without adopting future state or rewriting history.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if super::super::security_participant_state::output::exists(connection)? {
        return Err(invariant("pre-v32 native output catalog is unqualified"));
    }
    let has_global: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if has_global {
        let future: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'security_participant_output')", [], |row| row.get(0)).map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "pre-v32 native output references are unqualified",
            ));
        }
    }
    if on_disk == 31 {
        verify_admission_operation_schema(connection, 31)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::dpop_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::security_participant_migration::verify_all(connection)?;
        super::super::security_participant_state::egress::verify_catalog(connection)?;
        super::super::security_participant_state::dispatch_ledger::verify_all(connection)?;
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}
