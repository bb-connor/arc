//! Add empty inactive security-source history without adopting existing rows or
//! rewriting any admission event, replay activation or global commit digest.
use super::*;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let namespace: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
        WHERE lower(name) GLOB 'security_participant_migration*'
           OR lower(tbl_name) GLOB 'security_participant_migration*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if namespace {
        return Err(invariant(
            "pre-v27 schema contains unqualified security participant migration state",
        ));
    }
    let global: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
        WHERE type = 'table' AND lower(name) = 'authority_global_commits')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if global {
        let references: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits
            WHERE projection_kind = 'security_participant_migration')",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if references {
            return Err(invariant(
                "pre-v27 schema contains unqualified security migration references",
            ));
        }
    }
    if on_disk == 26 {
        verify_admission_operation_schema(connection, 26)?;
        verify_admission_operation_data_invariants(connection)?;
        super::super::runtime_participant::verify_all(connection)?;
        super::super::governed_approval_claim::verify_all(connection)?;
        super::super::dpop_claim::verify_all(connection)?;
        super::super::runtime_replay::verify_all_records(connection).map_err(invariant)?;
        super::super::governed_approval_replay::verify_all_records(connection)
            .map_err(invariant)?;
        super::super::dpop_replay::verify_all_records(connection).map_err(invariant)?;
    }
    Ok(())
}
