//! Exact terminal compaction preserves permanent spent-grant identity.

use super::*;

impl ScopedMutation<'_> {
    pub(super) fn compact_declassification_evidence(
        &self,
        request: &DeclassificationCompactionRequest,
    ) -> PortResult<DeclassificationEvidenceTombstone> {
        if request.readiness_cursor.as_str() != DECLASSIFICATION_READINESS_CURSOR
            || !matches!(
                request.terminal_state,
                DeclassificationUseState::Released | DeclassificationUseState::DispatchFailed
            )
        {
            return Err(PortError::invalid_data());
        }
        let transaction = self;
        let use_query = DeclassificationUseQuery {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
        };
        let use_record = load_declassification_use_record(transaction.reader(), &use_query)?
            .ok_or_else(PortError::invalid_data)?;
        let consumption = load_declassification_evidence_record(
            transaction.reader(),
            &DeclassificationEvidenceQuery {
                tenant_id: request.tenant_id.clone(),
                grant_id: request.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            },
        )?
        .ok_or_else(PortError::integrity_failure)?;
        let outcome = load_declassification_evidence_record(
            transaction.reader(),
            &DeclassificationEvidenceQuery {
                tenant_id: request.tenant_id.clone(),
                grant_id: request.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Outcome,
            },
        )?
        .ok_or_else(PortError::integrity_failure)?;
        let use_transition =
            load_declassification_use_transition(transaction.reader(), &use_query)?
                .ok_or_else(PortError::integrity_failure)?
                .ok_or_else(PortError::integrity_failure)?;
        records::verify_identity(transaction.reader(), &consumption)?;
        records::verify_identity(transaction.reader(), &outcome)?;
        let consumption_body = decode_declassification_receipt(&consumption.receipt)
            .map_err(|()| PortError::integrity_failure())?;
        let outcome_body = decode_declassification_receipt(&outcome.receipt)
            .map_err(|()| PortError::integrity_failure())?;
        let (
            ActiveDefenseReceiptBody::DeclassificationConsumption(consumption_body),
            ActiveDefenseReceiptBody::DeclassificationOutcome(outcome_body),
        ) = (consumption_body, outcome_body)
        else {
            return Err(PortError::integrity_failure());
        };
        let recovery_predecessor_matches = outcome
            .transition_binding
            .recovery_predecessor()
            .is_none_or(|(evidence_id, transition_id)| {
                evidence_id == &consumption.receipt.evidence_id
                    && transition_id == &consumption.receipt.transition_id
            });
        if use_record.request_hash != request.request_hash
            || use_record.state != request.terminal_state
            || use_record.consumption_binding != consumption.transition_binding
            || use_record.outcome_binding.as_ref() != Some(&outcome.transition_binding)
            || consumption.request_hash != use_record.request_hash
            || consumption.state != DeclassificationUseState::ConsumedPendingDispatch
            || consumption.receipt.occurred_at_unix_ms != use_record.consumed_at_unix_ms
            || outcome.request_hash != use_record.request_hash
            || outcome.state != use_record.state
            || outcome.transition_binding.terminal_state() != Some(use_record.state)
            || use_transition != outcome.receipt.transition_id
            || outcome.predecessor_evidence_id.as_ref() != Some(&consumption.receipt.evidence_id)
            || !recovery_predecessor_matches
            || request.compacted_at_unix_ms < use_record.retain_until_unix_ms
            || !consumption.acknowledged
            || !outcome.acknowledged
            || consumption.receipt.evidence_id != request.consumption_evidence_id
            || consumption.receipt.body_hash != request.consumption_body_hash
            || consumption.receipt.transition_id != request.consumption_transition_id
            || consumption.receipt.occurred_at_unix_ms != request.consumption_occurred_at_unix_ms
            || consumption.durable_sink_record_hash != Some(request.consumption_sink_record_hash)
            || outcome.receipt.evidence_id != request.outcome_evidence_id
            || outcome.receipt.body_hash != request.outcome_body_hash
            || outcome.receipt.transition_id != request.outcome_transition_id
            || outcome.receipt.occurred_at_unix_ms != request.outcome_occurred_at_unix_ms
            || outcome.durable_sink_record_hash != Some(request.outcome_sink_record_hash)
            || outcome.receipt.occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms
            || !receipt_pair_matches(&consumption_body, &outcome_body)
            || consumption_body.policy.policy_hash != request.policy_hash
        {
            return Err(PortError::conflict());
        }
        let activated = transaction
            .execute(sql::BEGIN_COMPACTION, &[])
            .map_err(sqlite_error)?;
        if activated != 1 {
            return Err(PortError::conflict());
        }
        transaction
            .execute(
                sql::INSERT_TOMBSTONE,
                params![
                    request.tenant_id.as_str(),
                    request.grant_id.as_str(),
                    request.request_hash.as_bytes().as_slice(),
                    declassification_state_name(request.terminal_state),
                    request.consumption_evidence_id.as_str(),
                    request.consumption_body_hash.as_bytes().as_slice(),
                    request.consumption_transition_id.as_str(),
                    to_i64(request.consumption_occurred_at_unix_ms)?,
                    request.consumption_sink_record_hash.as_bytes().as_slice(),
                    request.outcome_evidence_id.as_str(),
                    request.outcome_body_hash.as_bytes().as_slice(),
                    request.outcome_transition_id.as_str(),
                    to_i64(request.outcome_occurred_at_unix_ms)?,
                    request.outcome_sink_record_hash.as_bytes().as_slice(),
                    request.policy_hash.as_bytes().as_slice(),
                    to_i64(request.compacted_at_unix_ms)?,
                ],
            )
            .map_err(sqlite_error)?;
        let deleted_evidence = transaction
            .execute(
                sql::DELETE_EVIDENCE,
                params![request.tenant_id.as_str(), request.grant_id.as_str()],
            )
            .map_err(sqlite_error)?;
        let deleted_use = transaction
            .execute(
                sql::DELETE_USE,
                params![request.tenant_id.as_str(), request.grant_id.as_str()],
            )
            .map_err(sqlite_error)?;
        if deleted_evidence != 2 || deleted_use != 1 {
            return Err(PortError::integrity_failure());
        }
        let deactivated = transaction
            .execute(sql::END_COMPACTION, &[])
            .map_err(sqlite_error)?;
        if deactivated != 1 {
            return Err(PortError::integrity_failure());
        }
        let tombstone = DeclassificationEvidenceTombstone {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
            request_hash: request.request_hash,
            terminal_state: request.terminal_state,
            consumption_evidence_id: request.consumption_evidence_id.clone(),
            consumption_body_hash: request.consumption_body_hash,
            consumption_transition_id: request.consumption_transition_id.clone(),
            consumption_occurred_at_unix_ms: request.consumption_occurred_at_unix_ms,
            consumption_sink_record_hash: request.consumption_sink_record_hash,
            outcome_evidence_id: request.outcome_evidence_id.clone(),
            outcome_body_hash: request.outcome_body_hash,
            outcome_transition_id: request.outcome_transition_id.clone(),
            outcome_occurred_at_unix_ms: request.outcome_occurred_at_unix_ms,
            outcome_sink_record_hash: request.outcome_sink_record_hash,
            policy_hash: request.policy_hash,
            compacted_at_unix_ms: request.compacted_at_unix_ms,
        };
        Ok(tombstone)
    }
}

pub(super) fn candidates(
    connection: ScopedReader<'_>,
    query: &DeclassificationCompactionQuery,
) -> PortResult<Vec<DeclassificationCompactionCandidate>> {
    if query.readiness_cursor.as_str() != DECLASSIFICATION_READINESS_CURSOR
        || query.max_records == 0
        || query.max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH
        || query.after_tenant_id.is_some() != query.after_grant_id.is_some()
    {
        return Err(PortError::invalid_data());
    }
    lifecycle::verify(connection)?;
    integrity::verify(connection)?;
    let rows = match (&query.after_tenant_id, &query.after_grant_id) {
        (Some(tenant), Some(grant)) => connection.collect(
            sql::CANDIDATES_AFTER,
            params![
                to_i64(query.now_unix_ms)?,
                tenant.as_str(),
                grant.as_str(),
                i64::from(query.max_records)
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ),
        (None, None) => connection.collect(
            sql::CANDIDATES_FIRST,
            params![to_i64(query.now_unix_ms)?, i64::from(query.max_records)],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ),
        _ => return Err(PortError::invalid_data()),
    }
    .map_err(sqlite_error)?;
    rows.into_iter()
        .map(|(tenant_id, grant_id)| {
            let use_query = DeclassificationUseQuery {
                tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
                grant_id: GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?,
            };
            let use_record = load_declassification_use_record(connection, &use_query)?
                .ok_or_else(PortError::integrity_failure)?;
            let consumption = load_declassification_evidence_record(
                connection,
                &DeclassificationEvidenceQuery {
                    tenant_id: use_query.tenant_id.clone(),
                    grant_id: use_query.grant_id.clone(),
                    phase: DeclassificationEvidencePhase::Consumption,
                },
            )?
            .ok_or_else(PortError::integrity_failure)?;
            let outcome = load_declassification_evidence_record(
                connection,
                &DeclassificationEvidenceQuery {
                    tenant_id: use_query.tenant_id,
                    grant_id: use_query.grant_id,
                    phase: DeclassificationEvidencePhase::Outcome,
                },
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if !consumption.acknowledged || !outcome.acknowledged {
                return Err(PortError::conflict());
            }
            Ok(DeclassificationCompactionCandidate {
                readiness_cursor: query.readiness_cursor.clone(),
                use_record,
                consumption,
                outcome,
            })
        })
        .collect()
}
