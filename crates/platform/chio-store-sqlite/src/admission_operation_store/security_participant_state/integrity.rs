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
        let references: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = ?1)",
                [PROJECTION_KIND],
                |row| row.get(0),
            )
            .map_err(invalid)?;
        return if !references {
            Ok(())
        } else {
            Err(invalid("native references lack their catalog"))
        };
    }
    // Enclosing ordinary reads pin the current owner and rollback anchor.
    // Complete archives were authenticated at open. Recheck current rows,
    // checkpoint/suffix custody and indexed heads, never lifetime counts.
    let records = records::verify_all(connection).map_err(invalid)?;
    verify_initialization_references(connection, &records)?;
    let version: i32 = connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",[],|row|row.get(0)).map_err(invalid)?;
    let egress = super::egress::exists(connection).map_err(invalid)?;
    let output = super::output::exists(connection).map_err(invalid)?;
    let nonce = super::nonce_preflight::exists(connection).map_err(invalid)?;
    if (version >= 30 && !egress) || (version >= 32 && !output) || (version >= 33 && !nonce) {
        return Err(invalid("native journal family lacks its current catalog"));
    }
    if egress {
        super::egress::verify_catalog(connection).map_err(invalid)?;
    }
    if output {
        super::output::verify_catalog(connection).map_err(invalid)?;
    }
    if nonce {
        super::nonce_preflight::verify_catalog(connection).map_err(invalid)?;
    }
    for record in &records {
        let authority = record.authority.as_str();
        let checkpoint = super::checkpoint::latest(connection, authority).map_err(invalid)?;
        let heads = [
            super::history::head(connection, authority).map_err(invalid)?,
            if egress {
                super::egress::head(connection, authority).map_err(invalid)?
            } else {
                0
            },
            if output {
                super::output::head(connection, authority).map_err(invalid)?
            } else {
                0
            },
            if nonce {
                super::nonce_preflight::head(connection, authority).map_err(invalid)?
            } else {
                0
            },
        ];
        for (family, (kind, head)) in [
            "security_participant_state",
            "security_participant_egress",
            "security_participant_output",
            "security_participant_nonce_preflight",
        ]
        .into_iter()
        .zip(heads)
        .enumerate()
        {
            let global: i64 = connection.query_row("SELECT COALESCE(MAX(projection_sequence),0) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2",
                params![kind,authority],|row|row.get(0)).map_err(invalid)?;
            if u64::try_from(global).map_err(invalid)? != head {
                return Err(invalid("native family differs from its exact global head"));
            }
            if let Some(checkpoint) = &checkpoint {
                let sealed = &checkpoint.heads[family];
                if head == sealed.sequence && head > u64::from(family == 0) {
                    let exact: i64 = connection.query_row("SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3 AND projection_reference_digest = ?4 AND store_uuid = ?5",
                        params![kind,authority,i64::try_from(head).map_err(invalid)?,sealed.digest,record.fence.store_uuid],|row|row.get(0)).map_err(invalid)?;
                    if exact != 1 {
                        return Err(invalid("sealed native head lacks exact global custody"));
                    }
                }
            }
        }
    }
    super::checkpoint::verify_coverage(connection)?;
    Ok(())
}

/// Full archive rejection belongs to schema/open gates. Ordinary readback must
/// not turn retained history into lifetime work on every invocation.
pub(in crate::admission_operation_store) fn verify_archive_coverage(
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
    super::egress::verify_coverage(connection)?;
    super::output::verify_coverage(connection)?;
    super::nonce_preflight::verify_coverage(connection)?;
    super::checkpoint::verify_coverage(connection)?;
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
    verify_initialization_references(connection, records)
}

fn verify_initialization_references(
    connection: &Connection,
    records: &[SecurityParticipantStateInitialization],
) -> Result<(), SqliteServingOwnerError> {
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

pub(super) fn verify_event_reference(
    connection: &Connection,
    kind: &str,
    authority: &str,
    sequence: u64,
    mutation: &str,
    digest: &str,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let exact: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2
         AND projection_sequence = ?3 AND mutation_kind = ?4 AND projection_reference_digest = ?5
         AND store_uuid = ?6 AND store_lease_id = ?7 AND store_owner_epoch = ?8",
        params![kind,authority,i64::try_from(sequence).map_err(super::invalid)?,mutation,digest,
            fence.store_uuid,fence.lease_id,i64::try_from(fence.owner_epoch).map_err(super::invalid)?],|row|row.get(0),
    ).map_err(sqlite_error)?;
    if exact != 1 {
        return Err(super::invalid(
            "native historical event lacks its exact global commit",
        ));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    super::checkpoint::verify_pristine(connection)?;
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
