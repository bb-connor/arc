use super::*;

/// True if the non-audit `chio_dispatch_intents` journal table exists. A store
/// opened via `open_existing` on a pre-journal database runs no DDL, so a
/// missing table is reported as `false`; callers treat that as zero
/// open/dead-letter intents (an accurate report: a database that never
/// journaled has no orphans).
pub(crate) fn dispatch_intents_table_exists(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let name: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'chio_dispatch_intents'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(name.is_some())
}
