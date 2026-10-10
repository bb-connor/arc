//! A priced write must use the verified main database and its actual sources.
use super::*;

pub(super) const COMMAND_TABLES: [&str; 4] = [
    "admission_operation_recovery_records",
    "admission_operation_recovery_events",
    "authority_global_commits",
    "authority_global_commit_meta",
];

pub(super) fn require_command_namespace(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut databases = connection
        .prepare("PRAGMA database_list")
        .map_err(sqlite_error)?;
    let names = databases
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?;
    let mut main = false;
    for name in names {
        match name.map_err(sqlite_error)?.as_str() {
            "main" => main = true,
            "temp" => (),
            _ => {
                return Err(invariant(
                    "physical command profile contains an unpriced attached database",
                ));
            }
        }
    }
    if !main {
        return Err(invariant("physical command main database is unavailable"));
    }
    // Unrelated TEMP census objects are permitted. A TEMP trigger targeting a
    // priced table also executes on a main-qualified write, so qualification
    // alone cannot bound its additional writes.
    for table in COMMAND_TABLES {
        let unsupported: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
                 WHERE (type IN ('table','view') AND name=?1 COLLATE NOCASE)
                    OR (type='trigger' AND tbl_name=?1 COLLATE NOCASE))",
                [table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if unsupported {
            return Err(invariant(
                "physical command profile contains an unpriced temporary source or trigger",
            ));
        }
    }
    Ok(())
}
