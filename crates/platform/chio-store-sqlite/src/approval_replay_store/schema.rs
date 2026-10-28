use rusqlite::{Connection, OptionalExtension};

use super::SqliteApprovalReplayStoreError;

pub(super) const SCHEMA_KEY: &str = "settlement_approval_replay";

pub(super) const SCHEMA: &str = r#"
CREATE TABLE settlement_approval_replay_state (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    capacity INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 65536),
    high_water_unix_ms INTEGER NOT NULL CHECK (high_water_unix_ms >= 0)
) STRICT;
CREATE TABLE settlement_approval_replays (
    request_id TEXT NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 256
        AND trim(request_id) = request_id
        AND instr(request_id, char(0)) = 0
    ),
    intent_hash TEXT NOT NULL CHECK (
        length(intent_hash) = 64
        AND intent_hash NOT GLOB '*[^0-9a-f]*'
    ),
    expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > 0),
    PRIMARY KEY (request_id, intent_hash)
) STRICT;
CREATE INDEX settlement_approval_replay_expiry
    ON settlement_approval_replays(expires_at_unix_ms);
"#;

pub(super) fn validate_state(
    connection: &Connection,
    expected_capacity: usize,
) -> Result<i64, SqliteApprovalReplayStoreError> {
    let (capacity, high_water): (i64, i64) = connection
        .query_row(
            "SELECT capacity, high_water_unix_ms FROM settlement_approval_replay_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(SqliteApprovalReplayStoreError::InvalidState)?;
    if usize::try_from(capacity).ok() != Some(expected_capacity) {
        return Err(SqliteApprovalReplayStoreError::CapacityMismatch);
    }
    let state_rows: i64 = connection.query_row(
        "SELECT count(*) FROM settlement_approval_replay_state",
        [],
        |row| row.get(0),
    )?;
    let rows: i64 = connection.query_row(
        "SELECT count(*) FROM settlement_approval_replays",
        [],
        |row| row.get(0),
    )?;
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM settlement_approval_replays WHERE
            expires_at_unix_ms <= ?1 OR octet_length(request_id) NOT BETWEEN 1 AND 256
            OR trim(request_id) != request_id OR instr(request_id, char(0)) != 0
            OR length(intent_hash) != 64 OR intent_hash GLOB '*[^0-9a-f]*')",
        [high_water],
        |row| row.get(0),
    )?;
    if state_rows != 1 || high_water < 0 || rows < 0 || rows > capacity || invalid {
        return Err(SqliteApprovalReplayStoreError::InvalidState);
    }
    Ok(high_water)
}
