//! Introduce an empty runtime replay migration namespace without adopting
//! unqualified rows or repairing a damaged current predecessor schema.

use super::*;

#[cfg(test)]
mod tests;

pub(super) fn verify_pre_migration_schema(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let existing_namespace: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE lower(name) GLOB 'runtime_replay_*'
                OR lower(tbl_name) GLOB 'runtime_replay_*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if existing_namespace {
        return Err(invariant(
            "pre-v19 admission schema contains an unqualified runtime replay namespace",
        ));
    }
    // The v18 admission DDL itself is unchanged. Older supported versions still
    // pass through their existing migrations and final canonical verification.
    if on_disk == 18 {
        verify_admission_operation_schema(connection, 18)?;
        verify_admission_operation_data_invariants(connection)?;
    }
    Ok(())
}
