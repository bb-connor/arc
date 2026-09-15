use rusqlite::Connection;

use crate::replay_source::{
    RuntimeReplayMarker, RuntimeReplayMarkerKind, MAX_RUNTIME_REPLAY_SOURCE_BYTES,
    MAX_RUNTIME_REPLAY_SOURCE_MARKERS,
};

use super::{invalid, sqlite_error, ChioRuntimeError};

const MARKER_TABLES: [(&str, &str, RuntimeReplayMarkerKind); 3] = [
    (
        "runtime_consumed_leases",
        "lease_id",
        RuntimeReplayMarkerKind::DestructiveLease,
    ),
    (
        "runtime_consumed_treaty_continuations",
        "continuation_id",
        RuntimeReplayMarkerKind::TreatyContinuation,
    ),
    (
        "runtime_consumed_swarm_continuations",
        "continuation_id",
        RuntimeReplayMarkerKind::SwarmContinuation,
    ),
];

fn limit(detail: impl Into<String>) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_replay_source_inventory_limit",
        detail: detail.into(),
    }
}

pub(super) fn read_inventory(
    connection: &Connection,
) -> Result<Vec<RuntimeReplayMarker>, ChioRuntimeError> {
    let mut total_count = 0_usize;
    let mut total_bytes = 0_usize;
    for (table, resource, _) in MARKER_TABLES {
        let (count, bytes, invalid_fields): (i64, i64, i64) = connection
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(
                        length(CAST({resource} AS BLOB))
                        + length(CAST(admission_id AS BLOB))), 0),
                     COALESCE(SUM(CASE WHEN
                        typeof({resource}) <> 'text' OR typeof(admission_id) <> 'text'
                        OR length(CAST({resource} AS BLOB)) NOT BETWEEN 1 AND 512
                        OR length(CAST(admission_id AS BLOB)) NOT BETWEEN 1 AND 512
                     THEN 1 ELSE 0 END), 0) FROM {table}"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        if invalid_fields != 0 {
            return Err(invalid(
                "replay marker identifiers have invalid types or lengths",
            ));
        }
        total_count = total_count
            .checked_add(usize::try_from(count).map_err(|_| limit("invalid marker count"))?)
            .ok_or_else(|| limit("marker count overflows address space"))?;
        total_bytes = total_bytes
            .checked_add(usize::try_from(bytes).map_err(|_| limit("invalid marker bytes"))?)
            .ok_or_else(|| limit("marker bytes overflow address space"))?;
        if total_count > MAX_RUNTIME_REPLAY_SOURCE_MARKERS
            || total_bytes > MAX_RUNTIME_REPLAY_SOURCE_BYTES
        {
            return Err(limit("complete replay inventory exceeds its bounds"));
        }
    }

    let mut markers = Vec::with_capacity(total_count);
    for (table, resource, kind) in MARKER_TABLES {
        let mut statement = connection
            .prepare(&format!(
                "SELECT {resource}, admission_id FROM {table}
                 ORDER BY {resource} COLLATE BINARY, admission_id COLLATE BINARY"
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        for row in rows {
            let (resource_id, admission_id) = row.map_err(sqlite_error)?;
            markers.push(RuntimeReplayMarker::new(kind, resource_id, admission_id)?);
        }
    }
    if markers.len() != total_count {
        return Err(invalid("replay inventory changed within its snapshot"));
    }
    Ok(markers)
}
