//! Relational and canonical evidence checks in one selected authority.

use super::*;

pub(super) fn verify(connection: ScopedReader<'_>) -> PortResult<()> {
    let mut expected_evidence_count = 0_u64;
    connection.visit(sql::ALL_USES, |row| {
        let tenant_id = row.get::<_, String>(0).map_err(sqlite_error)?;
        let grant_id = row.get::<_, String>(1).map_err(sqlite_error)?;
        let query = DeclassificationUseQuery {
            tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
            grant_id: GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?,
        };
        let use_record = load_declassification_use_record(connection, &query)?
            .ok_or_else(PortError::integrity_failure)?;
        let use_transition = load_declassification_use_transition(connection, &query)?
            .ok_or_else(PortError::integrity_failure)?;
        let consumption = load_declassification_evidence_record(
            connection,
            &DeclassificationEvidenceQuery {
                tenant_id: query.tenant_id.clone(),
                grant_id: query.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            },
        )?
        .ok_or_else(PortError::integrity_failure)?;
        expected_evidence_count = expected_evidence_count
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        if consumption.request_hash != use_record.request_hash
            || consumption.state != DeclassificationUseState::ConsumedPendingDispatch
            || consumption.transition_binding != use_record.consumption_binding
            || consumption.predecessor_evidence_id.is_some()
            || consumption.receipt.occurred_at_unix_ms != use_record.consumed_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        let outcome = load_declassification_evidence_record(
            connection,
            &DeclassificationEvidenceQuery {
                tenant_id: query.tenant_id,
                grant_id: query.grant_id,
                phase: DeclassificationEvidencePhase::Outcome,
            },
        )?;
        match use_record.state {
            DeclassificationUseState::ConsumedPendingDispatch => {
                if use_transition.is_some() || outcome.is_some() {
                    return Err(PortError::integrity_failure());
                }
            }
            DeclassificationUseState::Released
            | DeclassificationUseState::DispatchFailed
            | DeclassificationUseState::OutcomeUnknown => {
                let outcome = outcome.ok_or_else(PortError::integrity_failure)?;
                expected_evidence_count = expected_evidence_count
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
                let recovery_predecessor_matches = outcome
                    .transition_binding
                    .recovery_predecessor()
                    .is_none_or(|(evidence_id, transition_id)| {
                        evidence_id == &consumption.receipt.evidence_id
                            && transition_id == &consumption.receipt.transition_id
                    });
                if outcome.request_hash != use_record.request_hash
                    || outcome.state != use_record.state
                    || use_record.outcome_binding.as_ref() != Some(&outcome.transition_binding)
                    || outcome.predecessor_evidence_id.as_ref()
                        != Some(&consumption.receipt.evidence_id)
                    || use_transition.as_ref() != Some(&outcome.receipt.transition_id)
                    || !recovery_predecessor_matches
                    || (outcome.acknowledged && !consumption.acknowledged)
                    || outcome.receipt.occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms
                {
                    return Err(PortError::integrity_failure());
                }
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
                if !receipt_pair_matches(&consumption_body, &outcome_body) {
                    return Err(PortError::integrity_failure());
                }
            }
        }
        Ok(())
    })?;
    let evidence_count = connection
        .query_row(sql::COUNT_EVIDENCE, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    if from_i64(evidence_count)? != expected_evidence_count {
        return Err(PortError::integrity_failure());
    }
    let mismatched_identity_count = connection
        .query_row(sql::MISMATCHED_IDENTITY, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    let tombstone_count = connection
        .query_row(sql::COUNT_TOMBSTONES, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    let simultaneous_live_tombstone_count = connection
        .query_row(sql::LIVE_TOMBSTONE, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    let invalid_tombstone_count = connection
        .query_row(sql::INVALID_TOMBSTONE, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    let identity_count = connection
        .query_row(sql::COUNT_IDENTITIES, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    let expected_identity_count = evidence_count
        .checked_add(
            tombstone_count
                .checked_mul(2)
                .ok_or_else(PortError::integrity_failure)?,
        )
        .ok_or_else(PortError::integrity_failure)?;
    if mismatched_identity_count != 0
        || simultaneous_live_tombstone_count != 0
        || invalid_tombstone_count != 0
        || identity_count != expected_identity_count
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}
