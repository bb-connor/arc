use super::*;


pub(super) fn transition_status(
    connection: &Connection,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<bool> {
    let existing: Option<(String, String, Vec<u8>)> = connection
        .query_row(
            "SELECT tenant_id, transition_kind, request_hash FROM security_transitions WHERE tenant_id = ?1 AND transition_id = ?2",
            params![tenant_id, transition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    check_transition_replay(existing, tenant_id, kind, request_hash)
}

pub(super) fn check_transition_replay(
    existing: Option<(String, String, Vec<u8>)>,
    tenant_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<bool> {
    if let Some((existing_tenant, existing_kind, existing_hash)) = existing {
        if existing_tenant == tenant_id
            && existing_kind == kind
            && existing_hash.as_slice() == request_hash
        {
            return Ok(true);
        }
        return Err(PortError::conflict());
    }
    Ok(false)
}

pub(super) fn record_transition(
    connection: &Connection,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    connection
        .execute(
            "INSERT INTO security_transitions (transition_id, tenant_id, transition_kind, request_hash) VALUES (?1, ?2, ?3, ?4)",
            params![transition_id, tenant_id, kind, request_hash.as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
