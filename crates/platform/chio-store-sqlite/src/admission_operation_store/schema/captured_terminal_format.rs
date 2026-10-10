//! Captured terminal custody and lossless journals share a strict successor.
use super::*;

pub(super) const TERMINAL_SQL: &str = include_str!("../../recovery_captured_terminal.sql");
pub(super) const ENCODING_SQL: &str = include_str!("../../recovery_knowledge_encoding.sql");

pub(super) fn verify_predecessor(
    connection: &Connection,
    version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if !(35..=38).contains(&version) {
        return Ok(());
    }
    verify_admission_operation_schema(connection, version)?;
    let future: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
         WHERE record_key GLOB 'captured-terminal:*' OR record_key GLOB 'captured-release:*'
           OR json_type(CAST(payload AS TEXT),'$.knowledge_join_encoding') IS NOT NULL
           OR json_type(CAST(payload AS TEXT),'$.checkpoint_restore_encoding') IS NOT NULL
           OR (record_key GLOB 'workflow-quota:*' AND (
             json_type(CAST(payload AS TEXT),'$.native_terminal') IS NOT NULL
             OR json_type(CAST(payload AS TEXT),'$.native_release') IS NOT NULL))
           OR (record_key GLOB 'recovery-workflow-allocation:*'
             AND json_type(CAST(payload AS TEXT),'$.retirement.captured_terminal') IS NOT NULL)
           OR (record_key GLOB 'command:*'
             AND json_type(CAST(payload AS TEXT),'$.reported_decision') IS NOT NULL))
         OR EXISTS(SELECT 1 FROM admission_operation_recovery_events
           WHERE record_key GLOB 'captured-terminal:*' OR record_key GLOB 'captured-release:*')
         OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery'
           AND (projection_key GLOB 'captured-terminal:*' OR projection_key GLOB 'captured-release:*'))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if future {
        return Err(invariant(
            "predecessor serving format contains future captured custody or encoding",
        ));
    }
    if version == 38 {
        verify_admission_operation_inventory(connection)?;
    }
    Ok(())
}
