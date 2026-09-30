//! Exact references and orphan checks for the independent nonce_preflight family.
use super::*;

pub(in crate::admission_operation_store::security_participant_state) fn verify_coverage(
    connection: &Connection,
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
    // The ordered row traversal authenticates each event and its exact global reference.
    Ok(())
}
