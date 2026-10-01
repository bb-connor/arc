//! Exact transition replay in the selected flow authority.

use super::*;

pub(super) fn scoped_transition_status(
    reader: FlowReader<'_>,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<bool> {
    let existing: Option<(String, String, Vec<u8>)> = reader
        .query_row(
            sql::LOAD_TRANSITION,
            params![tenant_id, transition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    check_transition_replay(existing, tenant_id, kind, request_hash)
}

pub(super) fn scoped_record_transition(
    mutation: &FlowMutation<'_>,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    mutation
        .execute(
            sql::INSERT_TRANSITION,
            params![transition_id, tenant_id, kind, request_hash.as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
