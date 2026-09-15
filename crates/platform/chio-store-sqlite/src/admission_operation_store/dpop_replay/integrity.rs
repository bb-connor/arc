//! Read-only linkage between locally verified migration history and the global
//! authority chain. Reference lookup deliberately never verifies global state:
//! the global verifier calls it while checking that same chain.

use rusqlite::{params, Connection};

use crate::serving_owner::SqliteServingOwnerError;

use super::{records, PROJECTION_KIND};

fn invalid(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("DPoP replay migration integrity: {detail}"))
}

/// Resolve exactly one retained local event, without recursing through the
/// authority anchor or global coverage verifier.
pub(crate) fn dpop_replay_projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let record = records::load_record(connection, key)
        .map_err(invalid)?
        .ok_or_else(|| invalid("global projection names an absent migration"))?;
    let event = record
        .events
        .iter()
        .find(|event| event.sequence == sequence)
        .ok_or_else(|| invalid("global projection names an absent migration event"))?;
    Ok(event.event_digest.clone())
}

/// Require a bijection between all local migration events and the corresponding
/// global commits, including the exact mutation, digest and historical fence.
pub(crate) fn verify_dpop_replay_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    verified_projection_records(connection).map(|_| ())
}

/// Reuse the exact records already decoded by complete coverage verification.
/// Nothing is cached across reads, transactions, callbacks or serving owners.
pub(super) fn verified_projection_records(
    connection: &Connection,
) -> Result<Vec<super::DpopReplayMigrationRecordV1>, SqliteServingOwnerError> {
    let records = records::verify_all_records(connection).map_err(invalid)?;
    let local_event_count = records.iter().try_fold(0_usize, |count, record| {
        count
            .checked_add(record.events.len())
            .ok_or_else(|| invalid("local migration event count overflow"))
    })?;
    let global_event_count = global_event_count(connection)?;
    if global_event_count != i64::try_from(local_event_count).map_err(invalid)? {
        return Err(invalid(
            "local migration events and global references have different counts",
        ));
    }
    // Older fixtures can lack the entire migration schema. A zero-reference
    // global catalog is enough in that case, without selecting event columns.
    if local_event_count == 0 {
        return Ok(records);
    }

    let mut statement = connection
        .prepare(
            "SELECT COUNT(*) FROM authority_global_commits
             WHERE projection_kind = ?1 AND projection_key = ?2
               AND projection_sequence = ?3 AND mutation_kind = ?4
               AND projection_reference_digest = ?5 AND store_uuid = ?6
               AND store_lease_id = ?7 AND store_owner_epoch = ?8",
        )
        .map_err(invalid)?;
    for record in &records {
        for event in &record.events {
            let matching: i64 = statement
                .query_row(
                    params![
                        PROJECTION_KIND,
                        record.snapshot.dpop_authority_id(),
                        i64::try_from(event.sequence).map_err(invalid)?,
                        &event.mutation_kind,
                        &event.event_digest,
                        &event.fence.store_uuid,
                        &event.fence.lease_id,
                        i64::try_from(event.fence.owner_epoch).map_err(invalid)?,
                    ],
                    |row| row.get(0),
                )
                .map_err(invalid)?;
            if matching != 1 {
                return Err(invalid(
                    "migration event lacks exactly one matching global commit",
                ));
            }
        }
    }
    Ok(records)
}

/// Provisioning may encounter no global schema yet, but only an entirely empty
/// locally verified migration state can qualify as pristine.
pub(crate) fn verify_dpop_replay_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    if !records::verify_all_records(connection)
        .map_err(invalid)?
        .is_empty()
    {
        return Err(invalid("DPoP replay migration state is not pristine"));
    }
    let global_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND lower(name) = 'authority_global_commits')",
            [],
            |row| row.get(0),
        )
        .map_err(invalid)?;
    if global_table_exists && global_event_count(connection)? != 0 {
        return Err(invalid(
            "pristine DPoP replay state has retained global migration references",
        ));
    }
    Ok(())
}

fn global_event_count(connection: &Connection) -> Result<i64, SqliteServingOwnerError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
            [PROJECTION_KIND],
            |row| row.get(0),
        )
        .map_err(invalid)
}
