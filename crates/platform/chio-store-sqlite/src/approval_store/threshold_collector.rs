//! Transactional persistence for the HTTP threshold approval collector.

use super::SqliteApprovalStore;
use chio_kernel::{
    ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorState,
    ThresholdApprovalCollectorStore, ThresholdApprovalCollectorStoreError,
};
use rusqlite::{params, TransactionBehavior};

mod snapshot;
use snapshot::load_collector;

fn collector_state_name(state: ThresholdApprovalCollectorState) -> &'static str {
    match state {
        ThresholdApprovalCollectorState::Collecting => "collecting",
        ThresholdApprovalCollectorState::Ready => "ready",
        ThresholdApprovalCollectorState::Delivered => "delivered",
        ThresholdApprovalCollectorState::Cancelled => "cancelled",
    }
}

fn collector_error(error: impl std::fmt::Display) -> ThresholdApprovalCollectorStoreError {
    ThresholdApprovalCollectorStoreError::Backend(error.to_string())
}

fn encode_collector<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, ThresholdApprovalCollectorStoreError> {
    chio_core::canonical::canonical_json_bytes(value)
        .map_err(|error| ThresholdApprovalCollectorStoreError::Serialization(error.to_string()))
}

fn decode_collector(
    bytes: &[u8],
) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
    serde_json::from_slice(bytes)
        .map_err(|error| ThresholdApprovalCollectorStoreError::Serialization(error.to_string()))
}

impl ThresholdApprovalCollectorStore for SqliteApprovalStore {
    fn create(
        &self,
        proposal: &ThresholdApprovalCollectorProposal,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let proposal_json = encode_collector(&proposal.proposal)?;
        let requirement_json = encode_collector(&proposal.requirement)?;
        let record_json = encode_collector(proposal)?;
        let mut conn = self.pool.get().map_err(collector_error)?;
        super::configure_reservation_connection(&conn).map_err(collector_error)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(collector_error)?;
        if let Some(existing) = load_collector(&transaction, &proposal.proposal.body.proposal_id)? {
            if !existing.registration_matches(proposal)? {
                return Err(ThresholdApprovalCollectorStoreError::Conflict(
                    "proposal id already exists with different content".to_string(),
                ));
            }
            transaction.commit().map_err(collector_error)?;
            return Ok(existing);
        }
        if !proposal.tokens.is_empty()
            || proposal.version != 0
            || proposal.state != ThresholdApprovalCollectorState::Collecting
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "new threshold approval proposal must start collecting without votes".to_string(),
            ));
        }
        let body = &proposal.proposal.body;
        transaction
            .execute(
                r#"
            INSERT INTO chio_threshold_approval_collectors (
                proposal_id, request_id, governed_intent_hash, subject_fingerprint,
                authorizing_capability_digest, policy_hash, threshold,
                eligible_set_digest, proposal_created_at, proposal_deadline,
                submitter_fingerprint, require_submitter_separation, state,
                version, updated_at, proposal_json, requirement_json, record_json
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18
            )
            "#,
                params![
                    &body.proposal_id,
                    &body.request_id,
                    &body.governed_intent_hash,
                    body.subject.to_hex(),
                    &body.authorizing_capability_digest,
                    &body.policy_hash,
                    i64::from(body.threshold),
                    &body.eligible_set_digest,
                    i64::try_from(body.proposal_created_at).map_err(collector_error)?,
                    i64::try_from(body.proposal_deadline).map_err(collector_error)?,
                    proposal.submitter.as_ref().map(|key| key.to_hex()),
                    i64::from(proposal.require_submitter_separation),
                    collector_state_name(proposal.state),
                    i64::try_from(proposal.version).map_err(collector_error)?,
                    i64::try_from(proposal.updated_at).map_err(collector_error)?,
                    proposal_json,
                    requirement_json,
                    record_json,
                ],
            )
            .map_err(collector_error)?;
        transaction.commit().map_err(collector_error)?;
        Ok(proposal.clone())
    }

    fn bind_request_route(
        &self,
        proposal_id: &str,
        expected_version: u64,
        route: &chio_kernel::threshold_approval::ThresholdApprovalRequest,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut conn = self.pool.get().map_err(collector_error)?;
        super::configure_reservation_connection(&conn).map_err(collector_error)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(collector_error)?;
        let mut record = load_collector(&transaction, proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.version != expected_version || record.request_route.is_some() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold proposal changed or already has an authenticated route".to_string(),
            ));
        }
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.request_route = Some(route.clone());
        let changed = transaction
            .execute(
                "UPDATE chio_threshold_approval_collectors SET version = ?1, record_json = ?2
             WHERE proposal_id = ?3 AND version = ?4",
                params![
                    i64::try_from(record.version).map_err(collector_error)?,
                    encode_collector(&record)?,
                    proposal_id,
                    i64::try_from(expected_version).map_err(collector_error)?,
                ],
            )
            .map_err(collector_error)?;
        if changed != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold proposal changed concurrently".into(),
            ));
        }
        transaction.commit().map_err(collector_error)?;
        Ok(record)
    }

    fn get(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        let mut conn = self.pool.get().map_err(collector_error)?;
        super::configure_reservation_connection(&conn).map_err(collector_error)?;
        let transaction = conn.transaction().map_err(collector_error)?;
        let record = load_collector(&transaction, proposal_id)?;
        transaction.commit().map_err(collector_error)?;
        Ok(record)
    }

    fn append_token(
        &self,
        proposal_id: &str,
        expected_version: u64,
        token: &chio_core::capability::governance::GovernedApprovalToken,
        replaced_token_id: Option<&str>,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut conn = self.pool.get().map_err(collector_error)?;
        super::configure_reservation_connection(&conn).map_err(collector_error)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(collector_error)?;
        let mut record = load_collector(&transaction, proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        let previous_state = collector_state_name(record.state);
        let token_digest = token.artifact_digest().map_err(|error| {
            ThresholdApprovalCollectorStoreError::Serialization(error.to_string())
        })?;
        let token_json = encode_collector(token)?;
        let write_result = if let Some(replaced_token_id) = replaced_token_id {
            transaction.execute(
                r#"
                UPDATE chio_threshold_approval_collector_votes
                SET token_id = ?1, approver_fingerprint = ?2,
                    canonical_token_digest = ?3, token_json = ?4, received_at = ?5
                WHERE proposal_id = ?6 AND token_id = ?7
                "#,
                params![
                    &token.id,
                    token.approver.to_hex(),
                    token_digest,
                    token_json,
                    i64::try_from(updated_at).map_err(collector_error)?,
                    proposal_id,
                    replaced_token_id,
                ],
            )
        } else {
            transaction.execute(
                r#"
                INSERT INTO chio_threshold_approval_collector_votes (
                    proposal_id, token_id, approver_fingerprint,
                    canonical_token_digest, token_json, received_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    proposal_id,
                    &token.id,
                    token.approver.to_hex(),
                    token_digest,
                    token_json,
                    i64::try_from(updated_at).map_err(collector_error)?,
                ],
            )
        };
        let changed_vote = write_result.map_err(|error| {
            if matches!(
                &error,
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::ConstraintViolation,
                        ..
                    },
                    _
                )
            ) {
                ThresholdApprovalCollectorStoreError::Conflict(
                    "threshold approval token id, digest, or signer is not unique".to_string(),
                )
            } else {
                collector_error(error)
            }
        })?;
        if changed_vote != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval replacement token disappeared".to_string(),
            ));
        }
        if let Some(replaced_token_id) = replaced_token_id {
            let existing = record
                .tokens
                .iter_mut()
                .find(|existing| existing.id == replaced_token_id)
                .ok_or_else(|| {
                    ThresholdApprovalCollectorStoreError::Conflict(
                        "threshold approval replacement token disappeared".to_string(),
                    )
                })?;
            *existing = token.clone();
        } else {
            record.tokens.push(token.clone());
        }
        record.state = next_state;
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.updated_at = updated_at;
        let record_json = encode_collector(&record)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE chio_threshold_approval_collectors
                SET state = ?1, version = ?2, updated_at = ?3, record_json = ?4
                WHERE proposal_id = ?5 AND version = ?6 AND state = ?7
                "#,
                params![
                    collector_state_name(next_state),
                    i64::try_from(record.version).map_err(collector_error)?,
                    i64::try_from(updated_at).map_err(collector_error)?,
                    record_json,
                    proposal_id,
                    i64::try_from(expected_version).map_err(collector_error)?,
                    previous_state,
                ],
            )
            .map_err(collector_error)?;
        if changed != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        transaction.commit().map_err(collector_error)?;
        Ok(record)
    }

    fn transition(
        &self,
        proposal_id: &str,
        expected_version: u64,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut conn = self.pool.get().map_err(collector_error)?;
        super::configure_reservation_connection(&conn).map_err(collector_error)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(collector_error)?;
        let mut record = load_collector(&transaction, proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        let previous_state = collector_state_name(record.state);
        record.state = next_state;
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.updated_at = updated_at;
        let record_json = encode_collector(&record)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE chio_threshold_approval_collectors
                SET state = ?1, version = ?2, updated_at = ?3, record_json = ?4
                WHERE proposal_id = ?5 AND version = ?6 AND state = ?7
                "#,
                params![
                    collector_state_name(next_state),
                    i64::try_from(record.version).map_err(collector_error)?,
                    i64::try_from(updated_at).map_err(collector_error)?,
                    record_json,
                    proposal_id,
                    i64::try_from(expected_version).map_err(collector_error)?,
                    previous_state,
                ],
            )
            .map_err(collector_error)?;
        if changed != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        transaction.commit().map_err(collector_error)?;
        Ok(record)
    }
}
