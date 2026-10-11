//! Introduce an empty native dispatch ledger, preserving all earlier history.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'admission_operation_native_dispatch*' OR lower(tbl_name) GLOB 'admission_operation_native_dispatch*')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v31 native dispatch ledger catalog is unqualified",
        ));
    }
    let has_global: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if has_global {
        let future: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'native_dispatch_ledger')", [], |row| row.get(0)).map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "pre-v31 native dispatch ledger references are unqualified",
            ));
        }
    }
    if on_disk == 30 {
        verify_admission_operation_schema(connection, 30)?;
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
        super::super::security_participant_state::verify_all(connection)?;
    }
    Ok(())
}
