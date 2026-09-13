//! Exact catalog, including inactive or alias-shaped partial future state.
use super::*;
use std::sync::OnceLock;

pub(in crate::admission_operation_store) fn sql() -> &'static str {
    include_str!("../../../admission_operation_security_participant_egress.sql")
}

pub(in crate::admission_operation_store) fn exists(
    connection: &Connection,
) -> Result<bool, AdmissionOperationStoreError> {
    connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'security_participant_egress*' OR lower(tbl_name) GLOB 'security_participant_egress*')", [], |row| row.get(0)).map_err(sqlite_error)
}

type Entry = (String, String, String, Option<String>);
fn catalog(connection: &Connection) -> Result<Vec<Entry>, AdmissionOperationStoreError> {
    let (count, bytes): (i64, i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(CAST(type AS BLOB)) + length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)), 0)), 0) FROM sqlite_schema WHERE lower(name) GLOB 'security_participant_egress*' OR lower(tbl_name) GLOB 'security_participant_egress*'", [], |row| Ok((row.get(0)?, row.get(1)?))).map_err(sqlite_error)?;
    if !(0..=16).contains(&count) || !(0..=1_048_576).contains(&bytes) {
        return Err(invalid("native egress catalog exceeds bounds"));
    }
    let mut statement = connection.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE lower(name) GLOB 'security_participant_egress*' OR lower(tbl_name) GLOB 'security_participant_egress*' ORDER BY type, name, tbl_name").map_err(sqlite_error)?;
    let result = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sqlite_error)?;
    Ok(result)
}

pub(in crate::admission_operation_store) fn verify_catalog(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    static EXPECTED: OnceLock<Result<Vec<Entry>, String>> = OnceLock::new();
    let expected = EXPECTED
        .get_or_init(|| {
            let memory = Connection::open_in_memory().map_err(|error| error.to_string())?;
            memory
                .execute_batch(sql())
                .map_err(|error| error.to_string())?;
            catalog(&memory).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(invalid)?;
    if &catalog(connection)? != expected {
        return Err(invalid("native egress catalog differs"));
    }
    Ok(())
}
