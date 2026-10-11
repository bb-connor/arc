//! Bound retained terminal payloads before copying them into Rust collections.
use super::*;
use rusqlite::types::ValueRef;

pub(super) struct StoredTerminalProjection {
    pub(super) source_operation_version: i64,
    pub(super) terminal_operation_version: i64,
    pub(super) terminal_state: String,
    pub(super) projection_body_digest: String,
    pub(super) projection_digest: String,
    pub(super) projection_json: Vec<u8>,
    pub(super) manifest_json: Vec<u8>,
    pub(super) record_count: i64,
    pub(super) committed_at_unix_ms: i64,
    pub(super) store_uuid: String,
    pub(super) store_lease_id: String,
    pub(super) store_owner_epoch: i64,
}

pub(super) struct StoredProjectionRecord {
    pub(super) kind: String,
    pub(super) record_id: String,
    pub(super) record_digest: String,
    pub(super) record_json: Vec<u8>,
}

pub(super) fn load_terminal_records(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Vec<StoredProjectionRecord>, AdmissionOperationStoreError> {
    let scan_limit = MAX_TERMINAL_RECORDS
        .checked_add(1)
        .and_then(|limit| i64::try_from(limit).ok())
        .ok_or_else(|| invariant("terminal record count limit overflow"))?;
    let count = preflight_terminal_records(connection, operation_id, scan_limit)?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records
            WHERE operation_id = ?1
            ORDER BY record_kind, record_id
            LIMIT ?2
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![operation_id.as_str(), scan_limit])
        .map_err(sqlite_error)?;
    let mut records = Vec::with_capacity(count);
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        checked_record_count(records.len())?;
        let bytes = bounded_blob(row, 3, MAX_TERMINAL_RECORD_BYTES, "terminal record")?;
        let kind = terminal_text(row, 0, MAX_ADMISSION_IDENTIFIER_BYTES, "record_kind")?;
        let record_id = terminal_text(row, 1, MAX_ADMISSION_IDENTIFIER_BYTES, "record_id")?;
        let record_digest = terminal_text(row, 2, 64, "record_digest")?;
        records.push(StoredProjectionRecord {
            kind: kind.to_owned(),
            record_id: record_id.to_owned(),
            record_digest: record_digest.to_owned(),
            record_json: bytes.to_vec(),
        });
    }
    if records.len() != count {
        return Err(invariant("terminal record count changed during its read"));
    }
    Ok(records)
}

fn checked_record_count(previous: usize) -> Result<usize, AdmissionOperationStoreError> {
    previous
        .checked_add(1)
        .filter(|count| *count <= MAX_TERMINAL_RECORDS)
        .ok_or_else(|| invariant("terminal record count exceeds its storage bounds"))
}

fn preflight_terminal_records(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    scan_limit: i64,
) -> Result<usize, AdmissionOperationStoreError> {
    // Inspect at most the existing count ceiling plus one sentinel row. SQLite
    // reports BLOB byte lengths without materializing payload vectors in Rust.
    let mut statement = connection
        .prepare(
            r#"
            SELECT typeof(record_json), length(record_json)
            FROM admission_operation_terminal_records
            WHERE operation_id = ?1
            ORDER BY record_kind, record_id
            LIMIT ?2
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![operation_id.as_str(), scan_limit])
        .map_err(sqlite_error)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        count = checked_record_count(count)?;
        if !matches!(
            row.get_ref(0).map_err(sqlite_error)?,
            ValueRef::Text(b"blob")
        ) {
            return Err(invariant("terminal record storage type is not a BLOB"));
        }
        let length: i64 = row.get(1).map_err(sqlite_error)?;
        if usize::try_from(length)
            .ok()
            .is_none_or(|length| length == 0 || length > MAX_TERMINAL_RECORD_BYTES)
        {
            return Err(invariant("terminal record exceeds its storage bounds"));
        }
    }
    Ok(count)
}

fn bounded_blob<'a>(
    row: &'a Row<'_>,
    column: usize,
    limit: usize,
    field: &str,
) -> Result<&'a [u8], AdmissionOperationStoreError> {
    match row.get_ref(column).map_err(sqlite_error)? {
        ValueRef::Blob(bytes) if !bytes.is_empty() && bytes.len() <= limit => Ok(bytes),
        _ => Err(invariant(format!(
            "{field} exceeds its BLOB storage bounds"
        ))),
    }
}

pub(super) fn terminal_text<'a>(
    row: &'a Row<'_>,
    column: usize,
    limit: usize,
    field: &str,
) -> Result<&'a str, AdmissionOperationStoreError> {
    let ValueRef::Text(bytes) = row.get_ref(column).map_err(sqlite_error)? else {
        return Err(invariant(format!(
            "terminal metadata {field} exceeds its TEXT storage bounds"
        )));
    };
    if bytes.is_empty() || bytes.len() > limit {
        return Err(invariant(format!(
            "terminal metadata {field} exceeds its TEXT storage bounds"
        )));
    }
    std::str::from_utf8(bytes).map_err(|error| {
        invariant(format!(
            "terminal metadata {field} is invalid UTF-8: {error}"
        ))
    })
}

pub(super) fn read_terminal_record_bytes(
    row: &Row<'_>,
    column: usize,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    bounded_blob(row, column, MAX_TERMINAL_RECORD_BYTES, "terminal record").map(<[u8]>::to_vec)
}

pub(super) fn load_terminal_projection_tx(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredTerminalProjection>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT source_operation_version, terminal_operation_version,
                   terminal_state, projection_body_digest, projection_digest,
                   projection_json, manifest_json, record_count,
                   committed_at_unix_ms, store_uuid, store_lease_id,
                   store_owner_epoch
            FROM admission_operation_terminal_projections
            WHERE operation_id = ?1
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([operation_id.as_str()])
        .map_err(sqlite_error)?;
    let Some(row) = rows.next().map_err(sqlite_error)? else {
        return Ok(None);
    };
    let record_count: i64 = row.get(7).map_err(sqlite_error)?;
    if usize::try_from(record_count)
        .ok()
        .is_none_or(|count| count == 0 || count > MAX_TERMINAL_RECORDS)
    {
        return Err(invariant(
            "terminal record count exceeds its storage bounds",
        ));
    }
    // Validate both borrowed payloads before copying either one.
    let projection = bounded_blob(row, 5, MAX_TERMINAL_PROJECTION_BYTES, "terminal projection")?;
    let manifest = bounded_blob(row, 6, MAX_TERMINAL_MANIFEST_BYTES, "terminal manifest")?;
    let terminal_state = terminal_text(row, 2, MAX_ADMISSION_IDENTIFIER_BYTES, "terminal_state")?;
    let projection_body_digest = terminal_text(row, 3, 64, "projection_body_digest")?;
    let projection_digest = terminal_text(row, 4, 64, "projection_digest")?;
    let store_uuid = terminal_text(row, 9, MAX_ADMISSION_IDENTIFIER_BYTES, "store_uuid")?;
    let store_lease_id = terminal_text(row, 10, MAX_ADMISSION_IDENTIFIER_BYTES, "store_lease_id")?;
    Ok(Some(StoredTerminalProjection {
        source_operation_version: row.get(0).map_err(sqlite_error)?,
        terminal_operation_version: row.get(1).map_err(sqlite_error)?,
        terminal_state: terminal_state.to_owned(),
        projection_body_digest: projection_body_digest.to_owned(),
        projection_digest: projection_digest.to_owned(),
        projection_json: projection.to_vec(),
        manifest_json: manifest.to_vec(),
        record_count,
        committed_at_unix_ms: row.get(8).map_err(sqlite_error)?,
        store_uuid: store_uuid.to_owned(),
        store_lease_id: store_lease_id.to_owned(),
        store_owner_epoch: row.get(11).map_err(sqlite_error)?,
    }))
}

#[cfg(test)]
#[path = "terminal_record_read_tests.rs"]
mod tests;
