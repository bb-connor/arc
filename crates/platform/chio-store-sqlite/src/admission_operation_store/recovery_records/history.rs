//! The immutable local event chain of protected records and its exact
//! coverage of every current projection.

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{Connection, OptionalExtension, Row};

use crate::serving_owner::SqliteServingOwnerError;

use super::digest::{event_digest, is_digest_hex, EventDigestInput};
use super::record::verify_present_record;
use super::{
    invariant, key_within_bounds, require_key, sqlite_error, sqlite_i64, stored_digest, stored_key,
    table_exists, EVENTS_TABLE, GENESIS_DIGEST, MAX_SAFE_INTEGER, RECORDS_TABLE,
};

/// One local event whose stored digest equals the v1 digest of its fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) struct RecordEvent {
    pub sequence: u64,
    pub record_key: String,
    pub record_version: u64,
    pub record_digest: String,
    pub previous_digest: String,
    pub event_digest: String,
    pub observed_at: u64,
}

pub(super) struct StoredEventRow {
    sequence: i64,
    record_key: Option<String>,
    record_version: i64,
    record_digest: Option<String>,
    previous_digest: Option<String>,
    event_digest: Option<String>,
    observed_at: i64,
}

/// Text columns are selected only within their type, character and byte bounds
/// and without NUL; integers only as integers. Other values read as absent or zero.
fn event_columns() -> String {
    let key = stored_key("record_key");
    let record_digest = stored_digest("record_digest");
    let previous_digest = stored_digest("previous_digest");
    let event_digest = stored_digest("event_digest");
    format!(
        "CASE WHEN typeof(sequence) = 'integer' THEN sequence ELSE 0 END,
         CASE WHEN {key} THEN record_key END,
         CASE WHEN typeof(record_version) = 'integer' THEN record_version ELSE 0 END,
         CASE WHEN {record_digest} THEN record_digest END,
         CASE WHEN {previous_digest} THEN previous_digest END,
         CASE WHEN {event_digest} THEN event_digest END,
         CASE WHEN typeof(observed_at) = 'integer' THEN observed_at ELSE 0 END"
    )
}

fn stored_event(row: &Row<'_>) -> rusqlite::Result<StoredEventRow> {
    Ok(StoredEventRow {
        sequence: row.get(0)?,
        record_key: row.get(1)?,
        record_version: row.get(2)?,
        record_digest: row.get(3)?,
        previous_digest: row.get(4)?,
        event_digest: row.get(5)?,
        observed_at: row.get(6)?,
    })
}

fn event_integer(value: i64) -> Option<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_SAFE_INTEGER).contains(value))
}

fn authenticate(row: StoredEventRow) -> Result<RecordEvent, AdmissionOperationStoreError> {
    let corrupt = || invariant("recovery history event is corrupt");
    let (Some(record_key), Some(record_digest), Some(previous_digest), Some(stored_digest)) = (
        row.record_key,
        row.record_digest,
        row.previous_digest,
        row.event_digest,
    ) else {
        return Err(invariant("recovery history event exceeds its bound"));
    };
    let (Some(sequence), Some(record_version), Some(observed_at)) = (
        event_integer(row.sequence),
        event_integer(row.record_version),
        event_integer(row.observed_at),
    ) else {
        return Err(corrupt());
    };
    if !key_within_bounds(&record_key)
        || ![&record_digest, &previous_digest, &stored_digest]
            .into_iter()
            .all(|digest| is_digest_hex(digest))
    {
        return Err(corrupt());
    }
    let computed = event_digest(&EventDigestInput {
        sequence,
        key: &record_key,
        version: record_version,
        record_digest: &record_digest,
        previous_digest: &previous_digest,
        observed_at,
    })?;
    if computed != stored_digest {
        return Err(corrupt());
    }
    Ok(RecordEvent {
        sequence,
        record_key,
        record_version,
        record_digest,
        previous_digest,
        event_digest: stored_digest,
        observed_at,
    })
}

pub(super) fn has_events(
    connection: &Connection,
    key: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM main.admission_operation_recovery_events WHERE record_key = ?1
             )",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// The bounded stored event of `key` at `version`, unauthenticated.
pub(super) fn stored_event_at(
    connection: &Connection,
    key: &str,
    version: i64,
) -> rusqlite::Result<Option<StoredEventRow>> {
    connection
        .query_row(
            &format!(
                "SELECT {} FROM main.admission_operation_recovery_events
                 WHERE record_key = ?1 AND record_version = ?2",
                event_columns()
            ),
            rusqlite::params![key, version],
            stored_event,
        )
        .optional()
}

/// The authenticated latest event of `key`, which must be at `version`. One
/// descending seek on the `(record_key, record_version)` index reads exactly
/// one event; continuity of the earlier history is `verify_local_history`'s.
pub(super) fn current_event(
    connection: &Connection,
    key: &str,
    version: u64,
) -> Result<RecordEvent, AdmissionOperationStoreError> {
    let latest = connection
        .query_row(
            &format!(
                "SELECT {} FROM main.admission_operation_recovery_events
                 WHERE record_key = ?1 ORDER BY record_version DESC LIMIT 1",
                event_columns()
            ),
            [key],
            stored_event,
        )
        .optional()
        .map_err(sqlite_error)?
        .map(authenticate)
        .transpose()?;
    match latest {
        Some(event) if event.record_key == key && event.record_version == version => Ok(event),
        _ => Err(invariant("recovery record history coverage is incomplete")),
    }
}

/// The global commit chain's reference for recovery projection `key` at
/// `sequence`: the authenticated digest of that record version's event.
pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let invalid = |detail: &str| SqliteServingOwnerError::Invalid(detail.to_owned());
    let integrity =
        |error: AdmissionOperationStoreError| SqliteServingOwnerError::Invalid(error.to_string());
    require_key(key).map_err(integrity)?;
    if !(1..=MAX_SAFE_INTEGER).contains(&sequence) {
        return Err(invalid(
            "recovery record projection reference version is out of range",
        ));
    }
    let version = sqlite_i64(sequence, "recovery record version").map_err(integrity)?;
    let row = stored_event_at(connection, key, version)?
        .ok_or_else(|| invalid("recovery record projection reference is absent"))?;
    let event = authenticate(row).map_err(integrity)?;
    let owned: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM main.admission_operation_recovery_records WHERE record_key = ?1
         )",
        [key],
        |row| row.get(0),
    )?;
    if !owned {
        return Err(invalid(
            "recovery record projection reference names an absent record",
        ));
    }
    Ok(event.event_digest)
}

/// Authenticate the whole local chain and every current projection. This
/// needs only the record catalog and runs before the global commit catalog is
/// initialized; global ownership is `verify_global_coverage`.
pub(in crate::admission_operation_store) fn verify_local_history(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if !table_exists(connection, RECORDS_TABLE)? || !table_exists(connection, EVENTS_TABLE)? {
        return Err(invariant("recovery record catalog is absent"));
    }
    verify_current_records(connection)?;
    verify_chain(connection)?;
    verify_version_continuity(connection)?;
    verify_coverage(connection)
}

fn verify_chain(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {} FROM main.admission_operation_recovery_events ORDER BY sequence",
            event_columns()
        ))
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut expected = 1_u64;
    let mut previous = GENESIS_DIGEST.to_owned();
    let mut observed = 0_u64;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let event = authenticate(stored_event(row).map_err(sqlite_error)?)?;
        if event.sequence != expected {
            return Err(invariant("recovery history sequence has a gap"));
        }
        if event.previous_digest != previous {
            return Err(invariant("recovery history link is broken"));
        }
        if event.observed_at < observed {
            return Err(invariant("recovery history time regressed"));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| invariant("recovery history sequence is exhausted"))?;
        previous = event.event_digest;
        observed = event.observed_at;
    }
    Ok(())
}

/// Each record's versions appear in sequence order as 1, 2, 3 and so on.
fn verify_version_continuity(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let broken: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM main.admission_operation_recovery_events AS event
                WHERE event.record_version > 1 AND NOT EXISTS(
                    SELECT 1 FROM main.admission_operation_recovery_events AS prior
                    WHERE prior.record_key = event.record_key
                      AND prior.record_version = event.record_version - 1
                      AND prior.sequence < event.sequence
                )
             )",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if broken {
        return Err(invariant("recovery record version is not contiguous"));
    }
    Ok(())
}

fn verify_coverage(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let incomplete: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM main.admission_operation_recovery_records AS record
                WHERE (
                    SELECT count(*) FROM main.admission_operation_recovery_events AS event
                    WHERE event.record_key = record.record_key
                ) <> record.version
                OR (
                    SELECT max(record_version) FROM main.admission_operation_recovery_events AS event
                    WHERE event.record_key = record.record_key
                ) IS NOT record.version
             )",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if incomplete {
        return Err(invariant("recovery record history coverage is incomplete"));
    }
    let orphaned: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM main.admission_operation_recovery_events AS event
                WHERE NOT EXISTS(
                    SELECT 1 FROM main.admission_operation_recovery_records AS record
                    WHERE record.record_key = event.record_key
                )
             )",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphaned {
        return Err(invariant("recovery history names an absent record"));
    }
    Ok(())
}

fn verify_current_records(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT CASE WHEN {} THEN record_key END
             FROM main.admission_operation_recovery_records ORDER BY record_key",
            stored_key("record_key")
        ))
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: Option<String> = row.get(0).map_err(sqlite_error)?;
        let key = key.ok_or_else(|| invariant("recovery record stored key exceeds its bound"))?;
        verify_present_record(connection, &key)?;
    }
    Ok(())
}
