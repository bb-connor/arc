//! Exact, non-recursive binding of every initialization to its global commit.
use super::*;

fn invalid(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("native security integrity: {detail}"))
}

pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    if sequence == 0 {
        return Err(invalid("native initialization sequence is invalid"));
    }
    if sequence > 1 {
        return super::history::load(connection, key, sequence)
            .map_err(invalid)?
            .ok_or_else(|| invalid("native mutation reference is absent"))?
            .digest()
            .map_err(invalid);
    }
    Ok(records::load_metadata(connection, key)
        .map_err(invalid)?
        .ok_or_else(|| invalid("native initialization reference is absent"))?
        .digest)
}

pub(in crate::admission_operation_store) fn verify_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    if !schema::verify(connection).map_err(invalid)? {
        return if global_count(connection)? == 0 {
            Ok(())
        } else {
            Err(invalid("native references lack their catalog"))
        };
    }
    let records = records::verify_all(connection).map_err(invalid)?;
    verify_initializations(connection, &records)?;
    let mutations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_participant_state_mutations",
            [],
            |row| row.get(0),
        )
        .map_err(invalid)?;
    if global_count(connection)? != i64::try_from(records.len()).map_err(invalid)? + mutations {
        return Err(invalid(
            "native initialization and global reference counts differ",
        ));
    }
    for initialized in &records {
        for sequence in
            2..=super::history::head(connection, initialized.authority.as_str()).map_err(invalid)?
        {
            let record = super::history::load(connection, initialized.authority.as_str(), sequence)
                .map_err(invalid)?
                .ok_or_else(|| invalid("native mutation disappeared"))?;
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2
                 AND projection_sequence = ?3 AND mutation_kind = ?4 AND projection_reference_digest = ?5
                 AND store_uuid = ?6 AND store_lease_id = ?7 AND store_owner_epoch = ?8",
                params![PROJECTION_KIND, record.authority.as_str(), i64::try_from(sequence).map_err(invalid)?,
                    super::history::MUTATION, record.digest().map_err(invalid)?, record.lease.fence.store_uuid,
                    record.lease.fence.lease_id, i64::try_from(record.lease.fence.owner_epoch).map_err(invalid)?], |row| row.get(0),
            ).map_err(invalid)?;
            if count != 1 {
                return Err(invalid("native mutation lacks its exact global commit"));
            }
        }
    }
    let orphans: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_mutations AS mutation
         WHERE NOT EXISTS(SELECT 1 FROM security_participant_state_initializations AS initialization
             WHERE initialization.security_authority_id = mutation.security_authority_id))",
            [],
            |row| row.get(0),
        )
        .map_err(invalid)?;
    if orphans {
        return Err(invalid("native mutation has no initialization"));
    }
    super::egress::verify_coverage(connection, &records)?;
    super::output::verify_coverage(connection, &records)?;
    Ok(())
}

pub(super) fn verify_initializations(
    connection: &Connection,
    records: &[SecurityParticipantStateInitialization],
) -> Result<(), SqliteServingOwnerError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_sequence = 1",
        [PROJECTION_KIND], |row| row.get(0),
    ).map_err(invalid)?;
    if count != i64::try_from(records.len()).map_err(invalid)? {
        return Err(invalid(
            "native initialization and global reference counts differ",
        ));
    }
    for record in records {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authority_global_commits
            WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = 1
              AND mutation_kind = ?3 AND projection_reference_digest = ?4 AND store_uuid = ?5
              AND store_lease_id = ?6 AND store_owner_epoch = ?7",
                params![
                    PROJECTION_KIND,
                    record.authority.as_str(),
                    MUTATION_KIND,
                    record.digest,
                    record.fence.store_uuid,
                    record.fence.lease_id,
                    i64::try_from(record.fence.owner_epoch).map_err(invalid)?
                ],
                |row| row.get(0),
            )
            .map_err(invalid)?;
        if count != 1 {
            return Err(invalid(
                "native initialization lacks its exact global commit",
            ));
        }
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    if !records::verify_all(connection).map_err(invalid)?.is_empty() {
        return Err(invalid("native state is not pristine"));
    }
    let global_exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND lower(name) = 'authority_global_commits')", [], |row| row.get(0)).map_err(invalid)?;
    if global_exists && global_count(connection)? != 0 {
        return Err(invalid("pristine state has native references"));
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
