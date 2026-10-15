//! Exactly one global authority commit per local recovery event, in event
//! order, referencing that event's digest.

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::Connection;

use super::{invariant, sqlite_error, sqlite_i64, stored_digest, stored_key, table_exists};

const GLOBAL_COMMITS_TABLE: &str = "authority_global_commits";
const RECOVERY_PROJECTION_KIND: &str = "recovery";
/// The one global mutation kind that publishes a recovery record version.
pub(super) const RECOVERY_MUTATION_KIND: &str = "recovery_transition";

/// Mandatory full-chain check, run after the global commit catalog exists
/// and after `verify_local_history` has authenticated every event digest.
pub(crate) fn verify_global_coverage(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if !table_exists(connection, GLOBAL_COMMITS_TABLE)? {
        return Err(invariant("recovery global commit catalog is absent"));
    }
    verify_event_ownership(connection)?;
    verify_no_orphan_commit(connection)
}

fn verify_event_ownership(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut events = connection
        .prepare(&format!(
            "SELECT
                CASE WHEN {} THEN record_key END,
                CASE WHEN typeof(record_version) = 'integer' THEN record_version ELSE 0 END,
                CASE WHEN {} THEN event_digest END
             FROM main.admission_operation_recovery_events ORDER BY sequence",
            stored_key("record_key"),
            stored_digest("event_digest")
        ))
        .map_err(sqlite_error)?;
    let mut commits = connection
        .prepare(&format!(
            "SELECT
                CASE WHEN typeof(commit_sequence) = 'integer' THEN commit_sequence ELSE 0 END,
                CASE WHEN {} THEN projection_reference_digest END,
                CASE WHEN typeof(mutation_kind) = 'text' AND mutation_kind = ?4
                    THEN 1 ELSE 0 END
             FROM main.authority_global_commits
             WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3
             ORDER BY commit_sequence LIMIT 2",
            stored_digest("projection_reference_digest")
        ))
        .map_err(sqlite_error)?;
    let mut rows = events.query([]).map_err(sqlite_error)?;
    let mut previous_commit = 0_i64;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let (Some(key), version, Some(event_digest)) = (
            row.get::<_, Option<String>>(0).map_err(sqlite_error)?,
            row.get::<_, i64>(1).map_err(sqlite_error)?,
            row.get::<_, Option<String>>(2).map_err(sqlite_error)?,
        ) else {
            return Err(invariant("recovery history event exceeds its bound"));
        };
        let version = u64::try_from(version)
            .ok()
            .filter(|version| *version > 0)
            .ok_or_else(|| invariant("recovery history event is corrupt"))?;
        let version = sqlite_i64(version, "recovery record version")?;
        let owners = commits
            .query_map(
                rusqlite::params![
                    RECOVERY_PROJECTION_KIND,
                    key,
                    version,
                    RECOVERY_MUTATION_KIND
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .map_err(sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_error)?;
        let [(commit, reference, mutation_matches)] = owners.as_slice() else {
            if owners.is_empty() {
                return Err(invariant("recovery event lacks its global commit"));
            }
            return Err(invariant("recovery event has duplicate global commits"));
        };
        if !*mutation_matches {
            return Err(invariant("recovery global commit mutation kind differs"));
        }
        let Some(reference) = reference else {
            return Err(invariant(
                "recovery global commit reference exceeds its bound",
            ));
        };
        if *reference != event_digest {
            return Err(invariant("recovery global commit reference differs"));
        }
        if *commit <= previous_commit {
            return Err(invariant("recovery global commit order regressed"));
        }
        previous_commit = *commit;
    }
    Ok(())
}

fn verify_no_orphan_commit(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let orphaned: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM main.authority_global_commits AS global
                WHERE global.projection_kind = ?1 AND NOT EXISTS(
                    SELECT 1 FROM main.admission_operation_recovery_events AS event
                    WHERE event.record_key = global.projection_key
                      AND event.record_version = global.projection_sequence
                )
             )",
            [RECOVERY_PROJECTION_KIND],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphaned {
        return Err(invariant("recovery global commit names an absent event"));
    }
    Ok(())
}
