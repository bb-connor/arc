use super::*;

pub(super) fn next_flow_generation(
    transaction: &FlowMutation<'_>,
    tenant_id: &str,
) -> PortResult<u64> {
    let sequence_generation: Option<i64> = transaction
        .query_row(sql::LOAD_SEQUENCE, params![tenant_id], |row| row.get(0))
        .optional()
        .map_err(sqlite_error)?;
    let stored_generation: Option<i64> = transaction
        .query_row(sql::MAX_GENERATION, params![tenant_id], |row| row.get(0))
        .map_err(sqlite_error)?;
    let current = sequence_generation
        .map(from_i64)
        .transpose()?
        .unwrap_or(0)
        .max(stored_generation.map(from_i64).transpose()?.unwrap_or(0));
    let next = current
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    transaction
        .execute(sql::STORE_SEQUENCE, params![tenant_id, to_i64(next)?])
        .map_err(sqlite_error)?;
    Ok(next)
}

pub(super) fn invalidate_related_flow_contexts(
    transaction: &FlowMutation<'_>,
    key: &FlowStateKey,
    generation: u64,
    principal_changed: bool,
    lineage_changed: bool,
    session_changed: bool,
) -> PortResult<()> {
    let generation = to_i64(generation)?;
    if principal_changed {
        transaction
            .execute(
                sql::INVALIDATE_PRINCIPAL,
                params![
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                    generation
                ],
            )
            .map_err(sqlite_error)?;
    }
    if lineage_changed {
        transaction
            .execute(
                sql::INVALIDATE_LINEAGE,
                params![key.tenant_id.as_str(), key.lineage_id.as_str(), generation],
            )
            .map_err(sqlite_error)?;
    }
    if session_changed {
        transaction
            .execute(
                sql::INVALIDATE_SESSION,
                params![
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.session_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                    generation
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

pub(super) fn store_context_generation(
    transaction: &FlowMutation<'_>,
    key: &FlowStateKey,
    generation: u64,
) -> PortResult<()> {
    transaction
        .execute(
            sql::STORE_CONTEXT,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
