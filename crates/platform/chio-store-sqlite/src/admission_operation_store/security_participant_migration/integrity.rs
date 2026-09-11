//! One-to-one linkage to the global rollback anchor. These local callbacks
//! never invoke the global verifier that is currently resolving them.
use crate::serving_owner::SqliteServingOwnerError;

use super::{records, Connection, PROJECTION_KIND};

fn invalid(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!(
        "security participant migration integrity: {detail}"
    ))
}

pub(crate) fn security_participant_projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let record = records::load(connection, key)
        .map_err(invalid)?
        .ok_or_else(|| invalid("global reference names an absent migration"))?;
    let event = record
        .events
        .iter()
        .find(|event| event.sequence == sequence)
        .ok_or_else(|| invalid("global reference names an absent migration event"))?;
    Ok(event.event_digest.clone())
}

pub(crate) fn verify_security_participant_migration_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    super::super::security_participant_state::verify_coverage(connection)?;
    let records = records::verify_all(connection).map_err(invalid)?;
    let local_count: usize = records.iter().map(|record| record.events.len()).sum();
    if global_count(connection)? != i64::try_from(local_count).map_err(invalid)? {
        return Err(invalid(
            "local migration events and global references differ",
        ));
    }
    if local_count == 0 {
        return Ok(());
    }
    let mut statement = connection
        .prepare(
            "SELECT COUNT(*) FROM authority_global_commits
        WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3
          AND mutation_kind = ?4 AND projection_reference_digest = ?5 AND store_uuid = ?6
          AND store_lease_id = ?7 AND store_owner_epoch = ?8",
        )
        .map_err(invalid)?;
    for record in records {
        for event in &record.events {
            let matches: i64 = statement
                .query_row(
                    rusqlite::params![
                        PROJECTION_KIND,
                        record.authority(),
                        i64::try_from(event.sequence).map_err(invalid)?,
                        event.mutation_kind,
                        event.event_digest,
                        event.fence.store_uuid,
                        event.fence.lease_id,
                        i64::try_from(event.fence.owner_epoch).map_err(invalid)?
                    ],
                    |row| row.get(0),
                )
                .map_err(invalid)?;
            if matches != 1 {
                return Err(invalid(
                    "migration lacks exactly one matching global commit",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_security_participant_migration_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    super::super::security_participant_state::verify_pristine(connection)?;
    if !records::verify_all(connection).map_err(invalid)?.is_empty() {
        return Err(invalid("migration state is not pristine"));
    }
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
        WHERE type = 'table' AND lower(name) = 'authority_global_commits')",
            [],
            |row| row.get(0),
        )
        .map_err(invalid)?;
    if exists && global_count(connection)? != 0 {
        return Err(invalid("pristine state has migration references"));
    }
    Ok(())
}

fn global_count(connection: &Connection) -> Result<i64, SqliteServingOwnerError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
            [PROJECTION_KIND],
            |row| row.get(0),
        )
        .map_err(invalid)
}
