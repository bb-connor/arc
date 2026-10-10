//! Verify the complete compiled marker catalog before any open-time repair.
use super::*;
pub(super) const SQL: &str = include_str!("schema.sql");
const NAMES: [&str; 5] = [
    "process_confined_delivery_markers",
    "process_confined_delivery_no_update",
    "process_confined_delivery_no_delete",
    "process_confined_delivery_version_requires_marker",
    "process_confined_delivery_version_no_downgrade",
];
pub(super) fn family_present(connection: &Connection) -> Result<bool, ProcessError> {
    connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name GLOB 'process_confined_delivery_*')",
        [], |row| row.get(0)).map_err(ProcessError::from)
}
pub(super) fn verify(connection: &Connection) -> Result<(), ProcessError> {
    super::super::unused_recovery_reservation::verify_retained_version_guard(connection)?;
    let compiled = Connection::open_in_memory()?;
    compiled.execute_batch(include_str!("../../store.sql"))?;
    compiled.execute_batch(SQL)?;
    for name in NAMES.into_iter().chain([
        "process_confined_return_slots",
        "process_confined_return_slot_identity_immutable",
        "process_confined_return_slot_no_delete",
    ]) {
        let expected: (String, String) = compiled.query_row(
            "SELECT type,sql FROM sqlite_schema WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let actual: Option<(String, String)> = connection
            .query_row(
                "SELECT type,sql FROM sqlite_schema WHERE name=?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if actual.as_ref() != Some(&expected) {
            return Err(ProcessError::Configuration(
                "confined delivery catalog changed",
            ));
        }
    }
    for suffix in [1, 2, 3] {
        let name = format!("sqlite_autoindex_process_confined_delivery_markers_{suffix}");
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1 AND tbl_name='process_confined_delivery_markers' AND sql IS NULL)",
            [name], |row| row.get(0))?;
        if !present {
            return Err(ProcessError::Configuration(
                "confined delivery indexes changed",
            ));
        }
    }
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'process_confined_delivery_*'",
        [],
        |row| row.get(0),
    )?;
    if usize::try_from(count).ok() != Some(NAMES.len()) {
        return Err(ProcessError::Configuration(
            "confined delivery inventory changed",
        ));
    }
    let attached: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE tbl_name='process_confined_delivery_markers'",
        [],
        |row| row.get(0),
    )?;
    if attached != 6 {
        return Err(ProcessError::Configuration(
            "confined delivery attached catalog changed",
        ));
    }
    Ok(())
}
