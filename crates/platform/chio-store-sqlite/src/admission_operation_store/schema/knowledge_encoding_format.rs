//! Lossless label atoms and logical references have an exact successor catalog.
use super::*;

pub(super) const ENCODING_SQL: &str = include_str!("../../recovery_knowledge_encoding_atoms.sql");
pub(super) const REFERENCE_SQL: &str = include_str!("../../recovery_reference_capacity.sql");
pub(super) const CHUNK_ACCOUNTING_SQL: &str =
    include_str!("../../recovery_knowledge_journal_chunk_accounting.sql");

// These families had no registered emitter in the supported predecessor.
// Existing pins, checkpoints, raw restores and actor-bound request keys retain
// their original bytes and remain eligible for authenticated legacy decoding.
const SUCCESSOR_KEYS: &[&str] = &[
    "knowledge-encoding-chunk:*",
    "knowledge-reference:*",
    "knowledge-reference-owner:*",
    "knowledge-reference-bucket:*",
    "knowledge-reference-ready:*",
    "knowledge-reference-capacity:*",
    "knowledge-checkpoint-head:*",
];

pub(super) fn verify_predecessor(
    connection: &Connection,
    version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if !(35..=39).contains(&version) {
        return Ok(());
    }
    verify_admission_operation_schema(connection, version)?;
    require_predecessor_absence(connection)?;
    if version == 39 {
        verify_admission_operation_inventory(connection)?;
    }
    Ok(())
}

pub(super) fn require_predecessor_absence(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    for pattern in SUCCESSOR_KEYS {
        let future: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB ?1)
             OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB ?1)
             OR EXISTS(SELECT 1 FROM authority_global_commits
                 WHERE projection_kind='recovery' AND projection_key GLOB ?1)",
            [pattern], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if future {
            return Err(invariant("predecessor contains future knowledge custody"));
        }
    }
    let future: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
         WHERE json_type(CAST(payload AS TEXT),'$.checkpoint_restore_encoding') IS NOT NULL
            OR json_type(CAST(payload AS TEXT),'$.knowledge_chunk_encoding') IS NOT NULL
            OR (json_type(CAST(payload AS TEXT),'$.knowledge_join_encoding') IS NOT NULL
             AND (json_type(CAST(payload AS TEXT),'$.knowledge_join_encoding') IS NOT 'text'
               OR json_extract(CAST(payload AS TEXT),'$.knowledge_join_encoding') IS NOT 'interned_labels_v1')))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if future {
        return Err(invariant("predecessor contains future knowledge encoding"));
    }
    Ok(())
}

/// Only the fenced migration calls this after exact predecessor verification.
/// Functional codec triggers replace the old journal-only contract atomically.
pub(super) fn install_current(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS admission_operation_recovery_codec_guard_insert;
         DROP TRIGGER IF EXISTS admission_operation_recovery_codec_guard_update;",
        )
        .map_err(sqlite_error)?;
    connection
        .execute_batch(ENCODING_SQL)
        .map_err(sqlite_error)?;
    connection
        .execute_batch(REFERENCE_SQL)
        .map_err(sqlite_error)?;
    connection
        .execute_batch(CHUNK_ACCOUNTING_SQL)
        .map_err(sqlite_error)
}

#[cfg(test)]
#[path = "knowledge_encoding_format_tests.rs"]
mod tests;
