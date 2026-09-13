//! Typed declassification rows in the selected data scope.

use super::*;

/// Validate the permanent identity before replacing live evidence with a tombstone.
pub(super) fn verify_identity(
    reader: ScopedReader<'_>,
    evidence: &DeclassificationEvidenceRecord,
) -> PortResult<()> {
    let matched: bool = reader
        .query_row(
            sql::MATCHING_IDENTITY,
            params![
                evidence.tenant_id.as_str(),
                evidence.receipt.evidence_id.as_str(),
                evidence.receipt.transition_id.as_str(),
                evidence.grant_id.as_str(),
                declassification_phase_name(evidence.phase),
                evidence.receipt.body_hash.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !matched {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn load_use(
    connection: ScopedReader<'_>,
    query: &DeclassificationUseQuery,
) -> PortResult<Option<DeclassificationUseRecord>> {
    type UseRow = (
        String,
        String,
        Vec<u8>,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
    );
    let row: Option<UseRow> = connection
        .query_row(
            sql::LOAD_USE,
            params![query.tenant_id.as_str(), query.grant_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        tenant_id,
        grant_id,
        request_hash,
        state,
        consumed_at,
        grant_expires_at,
        retain_until,
        consumption_binding,
        outcome_binding,
    )) = row
    else {
        return Ok(None);
    };
    let record = DeclassificationUseRecord {
        tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
        grant_id: GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?,
        request_hash: decode_digest(request_hash)?,
        state: parse_declassification_state(&state)?,
        consumed_at_unix_ms: from_i64(consumed_at)?,
        grant_expires_at_unix_ms: from_i64(grant_expires_at)?,
        retain_until_unix_ms: from_i64(retain_until)?,
        consumption_binding: decode_declassification_binding(&consumption_binding)?,
        outcome_binding: outcome_binding
            .as_deref()
            .map(decode_declassification_binding)
            .transpose()?,
    };
    if record.tenant_id != query.tenant_id
        || record.grant_id != query.grant_id
        || !record.consumption_binding.is_consumption()
        || record.consumption_binding.tenant_id() != &record.tenant_id
        || record.consumption_binding.grant_id() != &record.grant_id
        || record.consumption_binding.request_hash() != record.request_hash
        || record.grant_expires_at_unix_ms <= record.consumed_at_unix_ms
        || declassification_retain_until_unix_ms(record.grant_expires_at_unix_ms)
            != Ok(record.retain_until_unix_ms)
        || (record.state == DeclassificationUseState::ConsumedPendingDispatch)
            != record.outcome_binding.is_none()
        || record.outcome_binding.as_ref().is_some_and(|binding| {
            binding.terminal_state() != Some(record.state)
                || binding.tenant_id() != &record.tenant_id
                || binding.grant_id() != &record.grant_id
                || binding.request_hash() != record.request_hash
        })
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(record))
}

pub(super) fn load_transition(
    connection: ScopedReader<'_>,
    query: &DeclassificationUseQuery,
) -> PortResult<Option<Option<RecordId>>> {
    let value = connection
        .query_row(
            sql::LOAD_USE_TRANSITION,
            params![query.tenant_id.as_str(), query.grant_id.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    value
        .map(|transition_id| {
            transition_id
                .map(RecordId::new)
                .transpose()
                .map_err(|_| PortError::integrity_failure())
        })
        .transpose()
}

pub(super) fn insert_evidence(
    transaction: &ScopedMutation<'_>,
    evidence: &DeclassificationEvidenceCommit<'_>,
) -> PortResult<()> {
    let transition_binding = encode_declassification_binding(evidence.transition_binding)?;
    transaction
        .execute(
            sql::INSERT_IDENTITY,
            params![
                evidence.receipt.evidence_id.as_str(),
                evidence.receipt.transition_id.as_str(),
                evidence.tenant_id.as_str(),
                evidence.grant_id.as_str(),
                declassification_phase_name(evidence.phase),
                evidence.receipt.body_hash.as_bytes().as_slice(),
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            sql::INSERT_EVIDENCE,
            params![
                evidence.tenant_id.as_str(),
                evidence.grant_id.as_str(),
                declassification_phase_name(evidence.phase),
                i64::from(evidence.phase.ordinal()),
                evidence.request_hash.as_bytes().as_slice(),
                declassification_state_name(evidence.state),
                transition_binding,
                evidence.receipt.evidence_type.as_str(),
                evidence.receipt.evidence_id.as_str(),
                evidence.receipt.canonical_body.as_bytes(),
                evidence.receipt.body_hash.as_bytes().as_slice(),
                evidence.receipt.transition_id.as_str(),
                to_i64(evidence.receipt.occurred_at_unix_ms)?,
                evidence
                    .predecessor_evidence_id
                    .map(OpaqueReceiptRef::as_str),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn load_evidence(
    reader: ScopedReader<'_>,
    query: &DeclassificationEvidenceQuery,
) -> PortResult<Option<DeclassificationEvidenceRecord>> {
    reader
        .query_row(
            sql::LOAD_EVIDENCE,
            params![
                query.tenant_id.as_str(),
                query.grant_id.as_str(),
                i64::from(query.phase.ordinal())
            ],
            declassification_evidence_row,
        )
        .optional()
        .map_err(sqlite_error)?
        .map(decode_declassification_evidence_row)
        .transpose()
}

pub(super) fn pending(
    reader: ScopedReader<'_>,
    tenant_id: Option<&TenantId>,
    grant_id: Option<&GrantId>,
    now_unix_ms: u64,
    max_records: u32,
) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
    if max_records == 0 || max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH {
        return Err(PortError::invalid_data());
    }
    let now = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
    let limit = i64::from(max_records);
    let rows = match (tenant_id, grant_id) {
        (Some(tenant), Some(grant)) => reader.collect(
            sql::PENDING_GRANT,
            params![tenant.as_str(), grant.as_str(), now, limit],
            declassification_evidence_row,
        ),
        (None, None) => reader.collect(
            sql::PENDING_BATCH,
            params![now, limit],
            declassification_evidence_row,
        ),
        _ => return Err(PortError::invalid_data()),
    }
    .map_err(sqlite_error)?;
    rows.into_iter()
        .map(decode_declassification_evidence_row)
        .collect()
}
