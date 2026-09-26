//! Ordered evidence acknowledgement and bounded retry state.

use super::*;

impl ScopedMutation<'_> {
    pub(super) fn acknowledge_declassification_evidence(
        &self,
        request: &DeclassificationEvidenceAckRequest,
    ) -> PortResult<()> {
        let transaction = self;
        let query = DeclassificationEvidenceQuery {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
            phase: request.phase,
        };
        let record = load_declassification_evidence_record(transaction.reader(), &query)?
            .ok_or_else(PortError::invalid_data)?;
        if record.receipt.evidence_id != request.evidence_id
            || record.receipt.body_hash != request.body_hash
            || record.receipt.transition_id != request.transition_id
            || request.verified_at_unix_ms < record.receipt.occurred_at_unix_ms
            || request.durable_sink_record_hash == Digest32::new([0_u8; 32])
        {
            return Err(PortError::conflict());
        }
        if request.phase == DeclassificationEvidencePhase::Outcome {
            let predecessor = load_declassification_evidence_record(
                transaction.reader(),
                &DeclassificationEvidenceQuery {
                    tenant_id: request.tenant_id.clone(),
                    grant_id: request.grant_id.clone(),
                    phase: DeclassificationEvidencePhase::Consumption,
                },
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if record.predecessor_evidence_id.as_ref() != Some(&predecessor.receipt.evidence_id)
                || !predecessor.acknowledged
            {
                return Err(PortError::conflict());
            }
        }
        if record.acknowledged {
            if record.durable_sink_record_hash != Some(request.durable_sink_record_hash) {
                return Err(PortError::conflict());
            }
            return Ok(());
        }
        let updated = transaction
            .execute(
                sql::ACK_EVIDENCE,
                params![
                    request.tenant_id.as_str(),
                    request.grant_id.as_str(),
                    i64::from(request.phase.ordinal()),
                    request.evidence_id.as_str(),
                    request.body_hash.as_bytes().as_slice(),
                    request.transition_id.as_str(),
                    to_i64(request.verified_at_unix_ms)?,
                    request.durable_sink_record_hash.as_bytes().as_slice(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    pub(super) fn record_declassification_evidence_retry(
        &self,
        request: &DeclassificationEvidenceRetryRequest,
    ) -> PortResult<DeclassificationEvidenceRecord> {
        let transaction = self;
        let query = DeclassificationEvidenceQuery {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
            phase: request.phase,
        };
        let record = load_declassification_evidence_record(transaction.reader(), &query)?
            .ok_or_else(PortError::invalid_data)?;
        if record.acknowledged
            || record.receipt.evidence_id != request.evidence_id
            || record.receipt.body_hash != request.body_hash
            || record.receipt.transition_id != request.transition_id
            || request.failed_at_unix_ms < record.next_attempt_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        let attempts_after_failure = record
            .attempts
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let next_attempt_at_unix_ms = declassification_retry_deadline_unix_ms(
            request.failed_at_unix_ms,
            attempts_after_failure,
        )?;
        let updated = transaction
            .execute(
                sql::RETRY_EVIDENCE,
                params![
                    request.tenant_id.as_str(),
                    request.grant_id.as_str(),
                    i64::from(request.phase.ordinal()),
                    request.evidence_id.as_str(),
                    request.body_hash.as_bytes().as_slice(),
                    request.transition_id.as_str(),
                    i64::from(attempts_after_failure),
                    to_i64(next_attempt_at_unix_ms)?,
                    request.error_code.as_str(),
                    i64::from(record.attempts),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let updated_record = load_declassification_evidence_record(transaction.reader(), &query)?
            .ok_or_else(PortError::integrity_failure)?;
        Ok(updated_record)
    }
}

pub(super) fn stranded(
    connection: ScopedReader<'_>,
    max_records: u32,
) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
    if max_records == 0 || max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH {
        return Err(PortError::invalid_data());
    }
    connection
        .collect(
            sql::STRANDED_BATCH,
            params![i64::from(max_records)],
            declassification_evidence_row,
        )
        .map_err(sqlite_error)?
        .into_iter()
        .map(decode_declassification_evidence_row)
        .collect()
}

pub(super) fn count_pending(connection: ScopedReader<'_>) -> PortResult<u64> {
    let count = connection
        .query_row(sql::COUNT_PENDING, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    from_i64(count)
}

pub(super) fn count_stranded(connection: ScopedReader<'_>) -> PortResult<u64> {
    let count = connection
        .query_row(sql::COUNT_STRANDED, &[], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)?;
    from_i64(count)
}
