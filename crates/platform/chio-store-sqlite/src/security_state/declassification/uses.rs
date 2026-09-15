//! One-shot use and durable evidence in the caller-owned security transaction.

use super::*;

impl ScopedMutation<'_> {
    pub(in crate::security_state) fn commit_declassification_consumption_evidence(
        &self,
        request: &DeclassificationConsumptionEvidenceCommit,
        read_time: impl FnOnce() -> PortResult<u64>,
    ) -> PortResult<DeclassificationConsume> {
        validate_declassification_consumption_evidence(request)?;
        let retain_until_unix_ms =
            declassification_retain_until_unix_ms(request.consumption.grant_expires_at_unix_ms)?;
        let transaction = self;
        let live_dispatch: (i64, i64, i64) = transaction
            .query_row(sql::STATUS, &[], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(sqlite_error)?;
        if live_dispatch != (0, 1, 0) {
            return Err(PortError::conflict());
        }
        let query = DeclassificationUseQuery {
            tenant_id: request.consumption.tenant_id.clone(),
            grant_id: request.consumption.grant_id.clone(),
        };
        let evidence_query = DeclassificationEvidenceQuery {
            tenant_id: request.consumption.tenant_id.clone(),
            grant_id: request.consumption.grant_id.clone(),
            phase: DeclassificationEvidencePhase::Consumption,
        };
        let tombstoned: i64 = transaction
            .query_row(
                sql::HAS_TOMBSTONE,
                params![
                    request.consumption.tenant_id.as_str(),
                    request.consumption.grant_id.as_str(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if tombstoned != 0 {
            return Err(PortError::conflict());
        }
        let existing_use = load_declassification_use_record(transaction.reader(), &query)?;
        let existing_evidence =
            load_declassification_evidence_record(transaction.reader(), &evidence_query)?;
        match (existing_use, existing_evidence) {
            (None, None) => {
                let observed = read_time()?;
                if observed >= request.consumption.grant_expires_at_unix_ms {
                    return Err(PortError::conflict());
                }
                if observed.abs_diff(request.consumption.consumed_at_unix_ms) > MAX_CLOCK_SKEW_MS {
                    return Err(PortError::invalid_data());
                }
                transaction
                    .execute(
                        sql::INSERT_USE,
                        params![
                            request.consumption.grant_id.as_str(),
                            request.consumption.tenant_id.as_str(),
                            request.consumption.request_hash.as_bytes().as_slice(),
                            to_i64(request.consumption.consumed_at_unix_ms)?,
                            to_i64(request.consumption.grant_expires_at_unix_ms)?,
                            to_i64(retain_until_unix_ms)?,
                            encode_declassification_binding(&request.transition_binding)?,
                        ],
                    )
                    .map_err(sqlite_error)?;
                insert_declassification_evidence(
                    transaction,
                    &DeclassificationEvidenceCommit {
                        tenant_id: &request.consumption.tenant_id,
                        grant_id: &request.consumption.grant_id,
                        phase: DeclassificationEvidencePhase::Consumption,
                        request_hash: request.consumption.request_hash,
                        state: DeclassificationUseState::ConsumedPendingDispatch,
                        transition_binding: &request.transition_binding,
                        predecessor_evidence_id: None,
                        receipt: &request.receipt,
                    },
                )?;
                Ok(DeclassificationConsume::Consumed)
            }
            (Some(use_record), Some(evidence_record)) => {
                if use_record.request_hash != request.consumption.request_hash
                    || use_record.consumed_at_unix_ms != request.consumption.consumed_at_unix_ms
                    || use_record.grant_expires_at_unix_ms
                        != request.consumption.grant_expires_at_unix_ms
                    || use_record.retain_until_unix_ms != retain_until_unix_ms
                    || use_record.consumption_binding != request.transition_binding
                    || !declassification_evidence_matches(
                        &evidence_record,
                        &DeclassificationEvidenceCommit {
                            tenant_id: &request.consumption.tenant_id,
                            grant_id: &request.consumption.grant_id,
                            phase: DeclassificationEvidencePhase::Consumption,
                            request_hash: request.consumption.request_hash,
                            state: DeclassificationUseState::ConsumedPendingDispatch,
                            transition_binding: &request.transition_binding,
                            predecessor_evidence_id: None,
                            receipt: &request.receipt,
                        },
                    )
                {
                    return Err(PortError::conflict());
                }
                let state = use_record.state;
                Ok(DeclassificationConsume::AlreadyConsumed {
                    request_hash: request.consumption.request_hash,
                    state,
                })
            }
            (Some(_), None) | (None, Some(_)) => Err(PortError::integrity_failure()),
        }
    }

    pub(in crate::security_state) fn commit_declassification_outcome_evidence(
        &self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<()> {
        validate_declassification_outcome_evidence(request)?;
        let transaction = self;
        let lifecycle: (i64, i64, i64) = transaction
            .query_row(sql::STATUS, &[], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(sqlite_error)?;
        let lifecycle_valid = if request.transition_binding.is_live_dispatch_binding() {
            lifecycle == (0, 1, 0)
        } else {
            lifecycle == (1, 0, 0)
        };
        if !lifecycle_valid {
            return Err(PortError::conflict());
        }
        let use_query = DeclassificationUseQuery {
            tenant_id: request.outcome.tenant_id.clone(),
            grant_id: request.outcome.grant_id.clone(),
        };
        let consumption_query = DeclassificationEvidenceQuery {
            tenant_id: request.outcome.tenant_id.clone(),
            grant_id: request.outcome.grant_id.clone(),
            phase: DeclassificationEvidencePhase::Consumption,
        };
        let outcome_query = DeclassificationEvidenceQuery {
            phase: DeclassificationEvidencePhase::Outcome,
            ..consumption_query.clone()
        };
        let existing_use = load_declassification_use_record(transaction.reader(), &use_query)?;
        let existing_consumption =
            load_declassification_evidence_record(transaction.reader(), &consumption_query)?;
        let existing_outcome =
            load_declassification_evidence_record(transaction.reader(), &outcome_query)?;
        let Some(use_record) = existing_use else {
            return if existing_consumption.is_some() || existing_outcome.is_some() {
                Err(PortError::integrity_failure())
            } else {
                Err(PortError::invalid_data())
            };
        };
        if use_record.request_hash != request.outcome.request_hash {
            return Err(PortError::conflict());
        }
        let Some(consumption) = existing_consumption else {
            return Err(PortError::integrity_failure());
        };
        if consumption.request_hash != request.outcome.request_hash
            || consumption.receipt.evidence_id != request.predecessor_evidence_id
        {
            return Err(PortError::conflict());
        }
        if let Some((predecessor_evidence_id, predecessor_transition_id)) =
            request.transition_binding.recovery_predecessor()
        {
            if predecessor_evidence_id != &consumption.receipt.evidence_id
                || predecessor_transition_id != &consumption.receipt.transition_id
            {
                return Err(PortError::conflict());
            }
        }
        if request.receipt.occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms {
            return Err(PortError::invalid_data());
        }
        let consumption_body = decode_declassification_receipt(&consumption.receipt)
            .map_err(|()| PortError::integrity_failure())?;
        let outcome_body = decode_declassification_receipt(&request.receipt)
            .map_err(|()| PortError::invalid_data())?;
        let (
            ActiveDefenseReceiptBody::DeclassificationConsumption(consumption_body),
            ActiveDefenseReceiptBody::DeclassificationOutcome(outcome_body),
        ) = (consumption_body, outcome_body)
        else {
            return Err(PortError::integrity_failure());
        };
        if !receipt_pair_matches(&consumption_body, &outcome_body) {
            return Err(PortError::conflict());
        }
        let use_transition =
            load_declassification_use_transition(transaction.reader(), &use_query)?
                .ok_or_else(PortError::integrity_failure)?;
        if let Some(existing) = existing_outcome {
            if use_record.state != request.outcome.new_state
                || use_transition.as_ref() != Some(&request.outcome.transition_id)
                || use_record.outcome_binding.as_ref() != Some(&request.transition_binding)
                || !declassification_evidence_matches(
                    &existing,
                    &DeclassificationEvidenceCommit {
                        tenant_id: &request.outcome.tenant_id,
                        grant_id: &request.outcome.grant_id,
                        phase: DeclassificationEvidencePhase::Outcome,
                        request_hash: request.outcome.request_hash,
                        state: request.outcome.new_state,
                        transition_binding: &request.transition_binding,
                        predecessor_evidence_id: Some(&request.predecessor_evidence_id),
                        receipt: &request.receipt,
                    },
                )
            {
                return Err(PortError::conflict());
            }
            return Ok(());
        }
        if use_record.state != request.outcome.expected_state || use_transition.is_some() {
            return Err(PortError::integrity_failure());
        }
        let updated = transaction
            .execute(
                sql::UPDATE_OUTCOME,
                params![
                    request.outcome.grant_id.as_str(),
                    request.outcome.tenant_id.as_str(),
                    request.outcome.request_hash.as_bytes().as_slice(),
                    declassification_state_name(request.outcome.new_state),
                    request.outcome.transition_id.as_str(),
                    encode_declassification_binding(&request.transition_binding)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        insert_declassification_evidence(
            transaction,
            &DeclassificationEvidenceCommit {
                tenant_id: &request.outcome.tenant_id,
                grant_id: &request.outcome.grant_id,
                phase: DeclassificationEvidencePhase::Outcome,
                request_hash: request.outcome.request_hash,
                state: request.outcome.new_state,
                transition_binding: &request.transition_binding,
                predecessor_evidence_id: Some(&request.predecessor_evidence_id),
                receipt: &request.receipt,
            },
        )?;
        Ok(())
    }
}
