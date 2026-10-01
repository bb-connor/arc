//! Exact references and orphan checks for the independent nonce_preflight family.
use super::*;

pub(in crate::admission_operation_store::security_participant_state) fn verify_coverage(
    connection: &Connection,
    initialized: &[SecurityParticipantStateInitialization],
) -> Result<(), SqliteServingOwnerError> {
    let global: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
            [PROJECTION],
            |row| row.get(0),
        )
        .map_err(map_integrity)?;
    if !exists(connection).map_err(map_integrity)? {
        let version: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
            [], |row| row.get(0),
        ).map_err(map_integrity)?;
        return if global == 0 && version < 33 {
            Ok(())
        } else {
            Err(map_integrity(
                "native nonce preflight requires its current catalog",
            ))
        };
    }
    verify_catalog(connection).map_err(map_integrity)?;
    let local: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_participant_nonce_preflight_events",
            [],
            |row| row.get(0),
        )
        .map_err(map_integrity)?;
    if local != global {
        return Err(map_integrity(
            "native nonce preflight reference counts differ",
        ));
    }
    let orphans: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events AS event
        WHERE NOT EXISTS(SELECT 1 FROM security_participant_state_initializations AS initialization WHERE initialization.security_authority_id = event.security_authority_id))", [], |row| row.get(0)).map_err(map_integrity)?;
    if orphans {
        return Err(map_integrity(
            "native nonce preflight event lacks initialization",
        ));
    }
    for initialized in initialized {
        for sequence in
            1..=head(connection, initialized.authority.as_str()).map_err(map_integrity)?
        {
            let record = load(connection, initialized.authority.as_str(), sequence)
                .map_err(map_integrity)?
                .ok_or_else(|| map_integrity("native nonce preflight history disappeared"))?;
            let count: i64 = connection.query_row("SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3
                AND mutation_kind = ?4 AND projection_reference_digest = ?5 AND store_uuid = ?6 AND store_lease_id = ?7 AND store_owner_epoch = ?8",
                params![PROJECTION,initialized.authority.as_str(),i64::try_from(sequence).map_err(map_integrity)?,MUTATION,record.digest().map_err(map_integrity)?,record.lease.fence.store_uuid,record.lease.fence.lease_id,i64::try_from(record.lease.fence.owner_epoch).map_err(map_integrity)?], |row| row.get(0)).map_err(map_integrity)?;
            if count != 1 {
                return Err(map_integrity(
                    "native nonce preflight event lacks its exact global commit",
                ));
            }
        }
    }
    Ok(())
}
