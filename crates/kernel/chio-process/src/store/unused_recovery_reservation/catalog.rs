//! Retained closure guards match the compiled SQL before any open-time repair.
use super::*;

pub(super) const SQL: &str = include_str!("schema.sql");
const FAMILY_NAMES: [&str; 9] = [
    "process_unused_recovery_reservations",
    "process_unused_recovery_closure_no_update",
    "process_unused_recovery_closure_no_delete",
    "process_unused_recovery_no_call_insert",
    "process_unused_recovery_no_call_update",
    "process_unused_recovery_no_reservation_update",
    "process_unused_recovery_no_reservation_reinsert",
    "process_unused_recovery_version_requires_closure",
    "process_unused_recovery_version_no_downgrade",
];
const BACKING_NAMES: [&str; 2] = [
    "process_recovery_identity_immutable",
    "process_recovery_no_delete",
];

pub(super) fn family_present(connection: &Connection) -> Result<bool, ProcessError> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'process_unused_recovery_*'",
        [],
        |row| row.get(0),
    )?;
    let count = usize::try_from(count).map_err(|_| {
        ProcessError::Configuration("unused recovery closure inventory count is invalid")
    })?;
    Ok(count != 0)
}

pub(super) fn verify(connection: &Connection) -> Result<(), ProcessError> {
    // SQLite's own normalized catalog derives the expected exact table, index
    // and trigger definitions from compiled SQL, without normalizing literals.
    let compiled = Connection::open_in_memory()?;
    compiled.execute_batch(include_str!("../../store.sql"))?;
    compiled.execute_batch(SQL)?;
    verify_version_guard_against(connection, &compiled)?;
    for name in FAMILY_NAMES.into_iter().chain(BACKING_NAMES) {
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
                "unused recovery closure catalog changed",
            ));
        }
    }
    for name in [
        "sqlite_autoindex_process_unused_recovery_reservations_1",
        "sqlite_autoindex_process_unused_recovery_reservations_2",
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1 AND tbl_name='process_unused_recovery_reservations' AND sql IS NULL)",
            [name], |row| row.get(0),
        )?;
        if !present {
            return Err(ProcessError::Configuration(
                "unused recovery closure indexes changed",
            ));
        }
    }
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'process_unused_recovery_*'",
        [],
        |row| row.get(0),
    )?;
    let count = usize::try_from(count).map_err(|_| {
        ProcessError::Configuration("unused recovery closure inventory count is invalid")
    })?;
    if count != FAMILY_NAMES.len() {
        return Err(ProcessError::Configuration(
            "unused recovery closure inventory changed",
        ));
    }
    Ok(())
}

pub(super) fn verify_retained_version_guard(connection: &Connection) -> Result<(), ProcessError> {
    let compiled = Connection::open_in_memory()?;
    compiled.execute_batch(include_str!("../../store.sql"))?;
    verify_version_guard_against(connection, &compiled)
}

fn verify_version_guard_against(
    connection: &Connection,
    compiled: &Connection,
) -> Result<(), ProcessError> {
    let name = "process_recovery_version_monotone";
    let definition = |catalog: &Connection| -> Result<Option<(String, String)>, ProcessError> {
        Ok(catalog
            .query_row(
                "SELECT type,sql FROM sqlite_schema WHERE name=?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    };
    let actual = definition(connection)?;
    if actual == definition(compiled)? {
        return Ok(());
    }
    let version: u32 = connection.query_row(
        "SELECT version FROM process_runtime WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if matches!(version, 1..=6) {
        compiled.execute_batch("DROP TRIGGER process_recovery_version_monotone")?;
        compiled.execute_batch(include_str!("retained_version_guard.sql"))?;
        if actual == definition(compiled)? {
            return Ok(());
        }
    }
    Err(ProcessError::Configuration(
        "unused recovery version guard changed",
    ))
}
