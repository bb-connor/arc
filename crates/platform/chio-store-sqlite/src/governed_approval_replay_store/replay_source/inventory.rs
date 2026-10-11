use chio_kernel::admission_operation::AdmissionIdentifier;
use rusqlite::Connection;

use super::{
    evidence::{Inventory, Marker, MAX_BYTES, MAX_MARKERS},
    invalid, Error,
};

pub(super) fn read(connection: &Connection) -> Result<Inventory, Error> {
    // Inspect storage types and byte lengths before allocating untrusted text.
    // NULLs in primary-key text remain possible in malformed legacy schemas;
    // the exact schema check is a separate prerequisite, not a substitute here.
    let (count, bytes, invalid_rows): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(subject_id AS BLOB))
            + length(CAST(request_id AS BLOB)) + length(CAST(intent_hash AS BLOB))
            + COALESCE(length(CAST(dispatch_reservation_id AS BLOB)), 0)), 0),
            COALESCE(SUM(CASE WHEN typeof(subject_id) = 'text'
                AND typeof(request_id) = 'text' AND typeof(intent_hash) = 'text'
                AND typeof(expires_at) = 'integer' AND expires_at >= 0
                AND length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 512
                AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 512
                AND length(CAST(intent_hash AS BLOB)) BETWEEN 1 AND 512
                AND (dispatch_reservation_id IS NULL OR
                    (typeof(dispatch_reservation_id) = 'text'
                    AND length(CAST(dispatch_reservation_id AS BLOB)) BETWEEN 1 AND 512))
                THEN 0 ELSE 1 END), 0)
         FROM chio_governed_approval_replay_entries",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let count = usize::try_from(count).map_err(|_| invalid("invalid marker count"))?;
    let bytes = usize::try_from(bytes).map_err(|_| invalid("invalid marker size"))?;
    if count > MAX_MARKERS || bytes > MAX_BYTES || invalid_rows != 0 {
        return Err(invalid(
            "markers exceed bounds or contain invalid storage types",
        ));
    }
    for table in [
        "chio_governed_approval_replay_clock",
        "chio_governed_approval_replay_limits",
    ] {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        if count != 1 {
            return Err(invalid("replay metadata must contain exactly one row"));
        }
    }
    let (high_water, pruned): (i64, i64) = connection.query_row(
        "SELECT wall_clock_high_water, pruned_through FROM chio_governed_approval_replay_clock
         WHERE singleton = 1 AND typeof(wall_clock_high_water) = 'integer'
         AND typeof(pruned_through) = 'integer'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let capacity: i64 = connection.query_row(
        "SELECT capacity FROM chio_governed_approval_replay_limits WHERE singleton = 1
         AND typeof(capacity) = 'integer'",
        [],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT subject_id, request_id, intent_hash, expires_at, dispatch_reservation_id
         FROM chio_governed_approval_replay_entries
         ORDER BY subject_id COLLATE BINARY, request_id COLLATE BINARY, intent_hash COLLATE BINARY",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut markers = Vec::with_capacity(count);
    for row in rows {
        let (subject, request, intent, expiry, owner) = row?;
        markers.push(Marker {
            subject_id: identifier(subject)?,
            request_id: identifier(request)?,
            intent_hash: identifier(intent)?,
            expires_at: expiry.to_string(),
            dispatch_reservation_id: owner.map(identifier).transpose()?,
        });
    }
    Ok(Inventory {
        wall_clock_high_water: high_water.to_string(),
        pruned_through: pruned.to_string(),
        capacity: capacity.to_string(),
        markers,
    })
}

fn identifier(value: String) -> Result<AdmissionIdentifier, Error> {
    AdmissionIdentifier::try_new("approval_replay_inventory_identifier", value)
        .map_err(|_| invalid("invalid replay marker identifier"))
}
