use super::*;

pub(super) fn load_scoped_flow_snapshot(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<Option<FlowStateSnapshot>> {
    let epoch_exists = isolation_epoch_exists(connection, key)?;
    let principal = load_principal_label(connection, key)?;
    let lineage = load_lineage_label(connection, key)?;
    let session = load_session_label(connection, key)?;
    let session_membership = session_membership_exists(connection, key)?;
    let context_generation = load_context_generation(connection, key)?;
    if !epoch_exists {
        if principal.is_some()
            || session.is_some()
            || session_membership
            || context_generation.is_some()
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(None);
    }
    if session.is_some() != session_membership {
        return Err(PortError::integrity_failure());
    }
    let (principal_label, principal_generation) =
        principal.ok_or_else(PortError::integrity_failure)?;
    let (lineage_label, lineage_generation) = lineage.ok_or_else(PortError::integrity_failure)?;
    let Some(context_generation) = context_generation else {
        if session.is_some() {
            return Err(PortError::integrity_failure());
        }
        let session_label = principal_label
            .join_restrictions(&lineage_label)
            .map_err(|_| PortError::integrity_failure())?;
        return Ok(Some(FlowStateSnapshot {
            key: key.clone(),
            principal_label,
            lineage_label,
            session_label,
            context_generation: principal_generation.max(lineage_generation),
        }));
    };
    let (stored_session_label, session_generation) =
        session.ok_or_else(PortError::integrity_failure)?;
    if principal_generation > context_generation
        || lineage_generation > context_generation
        || session_generation > context_generation
    {
        return Err(PortError::integrity_failure());
    }
    let session_label = stored_session_label
        .join_restrictions(&principal_label)
        .and_then(|label| label.join_restrictions(&lineage_label))
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Some(FlowStateSnapshot {
        key: key.clone(),
        principal_label,
        lineage_label,
        session_label,
        context_generation,
    }))
}

pub(super) fn store_principal_label(
    transaction: &FlowMutation<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            sql::STORE_PRINCIPAL,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn store_lineage_label(
    transaction: &FlowMutation<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            sql::STORE_LINEAGE,
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn store_session_label(
    transaction: &FlowMutation<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            sql::STORE_MEMBERSHIP,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            sql::STORE_SESSION,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

type StoredLabel = (Vec<u8>, Vec<u8>, i64);

fn decode_flow_generation(generation: i64) -> PortResult<u64> {
    if generation <= 0 {
        return Err(PortError::integrity_failure());
    }
    from_i64(generation)
}

pub(super) fn load_principal_label(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            sql::LOAD_PRINCIPAL,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| {
            Ok((
                decode_label(body, hash)?,
                decode_flow_generation(generation)?,
            ))
        })
        .transpose()
}

pub(super) fn load_lineage_label(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            sql::LOAD_LINEAGE,
            params![key.tenant_id.as_str(), key.lineage_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| {
            Ok((
                decode_label(body, hash)?,
                decode_flow_generation(generation)?,
            ))
        })
        .transpose()
}

pub(super) fn load_session_label(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            sql::LOAD_SESSION,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| {
            Ok((
                decode_label(body, hash)?,
                decode_flow_generation(generation)?,
            ))
        })
        .transpose()
}

pub(super) fn load_context_generation(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<Option<u64>> {
    let generation: Option<i64> = connection
        .query_row(
            sql::LOAD_CONTEXT,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    generation.map(decode_flow_generation).transpose()
}

pub(super) fn session_membership_exists(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<bool> {
    connection
        .query_row(
            sql::HAS_MEMBERSHIP,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

pub(super) fn isolation_epoch_exists(
    connection: FlowReader<'_>,
    key: &FlowStateKey,
) -> PortResult<bool> {
    connection
        .query_row(
            sql::HAS_EPOCH,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}
