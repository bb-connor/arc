use super::*;
use std::sync::OnceLock;

const NAMESPACE: &str = "lower(name) GLOB 'security_participant_checkpoint*' OR lower(tbl_name) GLOB 'security_participant_checkpoint*'";
type Entry = (String, String, String, Option<String>);

pub(in crate::admission_operation_store) fn sql() -> &'static str {
    include_str!("schema.sql")
}

fn catalog(connection: &Connection) -> Result<Vec<Entry>, AdmissionOperationStoreError> {
    let (count, bytes): (i64, i64) = connection.query_row(
        &format!("SELECT COUNT(*), COALESCE(SUM(length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)),0)),0) FROM sqlite_schema WHERE {NAMESPACE}"),
        [], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(sqlite_error)?;
    if !(0..=32).contains(&count) || !(0..=131_072).contains(&bytes) {
        return Err(invalid("native checkpoint catalog exceeds bounds"));
    }
    let mut statement = connection.prepare(&format!(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE {NAMESPACE} ORDER BY type,name,tbl_name"
    )).map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

pub(in crate::admission_operation_store) fn require_absent(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if !catalog(connection)?.is_empty() {
        return Err(invalid("pre-v36 native checkpoint catalog is unqualified"));
    }
    Ok(())
}

pub(super) fn present(connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    let actual = catalog(connection)?;
    if actual.is_empty() {
        let versions: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'chio_store_schema_versions')",[],|row|row.get(0)).map_err(sqlite_error)?;
        let version: Option<i32> = if versions {
            connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
            [], |row| row.get(0),
        ).optional().map_err(sqlite_error)?
        } else {
            None
        };
        if version.is_some_and(|version| version >= 36) {
            return Err(invalid("native checkpoint catalog is absent"));
        }
        return Ok(false);
    }
    verify_catalog(connection)?;
    Ok(true)
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
        return Err(invalid("native checkpoint catalog is not canonical"));
    }
    Ok(())
}
