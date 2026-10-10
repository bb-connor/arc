//! The supported recovery catalog is installed as one atomic native extension.
use super::*;

pub(super) fn install(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    for sql in [
        super::super::recovery::SQL,
        super::super::recovery::deployment_history::SQL,
        super::super::recovery::historical_holds::SQL,
        include_str!("../../recovery_origin_presence.sql"),
        include_str!("../../recovery_command_alias.sql"),
        include_str!("../../recovery_captured_terminal.sql"),
        include_str!("../../recovery_knowledge_encoding_atoms.sql"),
        include_str!("../../recovery_reference_capacity.sql"),
        include_str!("../../recovery_knowledge_journal_chunk_accounting.sql"),
    ] {
        connection.execute_batch(sql).map_err(sqlite_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
