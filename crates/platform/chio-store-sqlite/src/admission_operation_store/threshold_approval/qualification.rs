//! Threshold reservation owns only its approval attachments, including on retry.

use super::*;
use chio_kernel::ThresholdApprovalReplayReservationV1;

pub(super) fn qualify_command(
    command: &AdmissionOperationCommand,
    reservation: &ThresholdApprovalReplayReservationV1,
    trusted_now_unix_ms: u64,
) -> Result<(String, String), AdmissionOperationStoreError> {
    let proposal_hash = reservation
        .proposal()
        .artifact_digest()
        .map_err(|error| invariant(error.to_string()))?;
    let approval_set_hash = reservation
        .verified_set()
        .approval_set_hash()
        .map_err(|error| invariant(error.to_string()))?;
    if command.next_state() != Some(AdmissionOperationState::ApprovalReserved)
        || command.attachments().len() != 2
        || command.terminal_replay().is_some()
        || command.last_error().is_some()
        || !command.attachments().iter().any(|attachment| {
            matches!(attachment,
            AdmissionAttachment::ThresholdProposalHash(digest) if digest.as_str() == proposal_hash)
        })
        || !command.attachments().iter().any(|attachment| {
            matches!(attachment,
            AdmissionAttachment::ApprovalSetHash(digest) if digest.as_str() == approval_set_hash)
        })
    {
        return Err(invariant(
            "threshold reservation requires its exact approval-only command",
        ));
    }
    let now = trusted_now_unix_ms / 1_000;
    let proposal = &reservation.proposal().body;
    if now < proposal.proposal_created_at
        || now >= proposal.proposal_deadline
        || reservation
            .tokens()
            .iter()
            .any(|token| now < token.issued_at || now >= token.expires_at)
    {
        return Err(invariant(
            "threshold reservation requires currently valid proposal and tokens",
        ));
    }
    Ok((proposal_hash, approval_set_hash))
}

/// Equality is checked inside SQLite, so corrupt stored blobs are not allocated
/// into Rust. Matching operation metadata alone cannot prove a reservation.
pub(super) fn verify_exact_replay(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    reservation: &ThresholdApprovalReplayReservationV1,
    proposal_hash: &str,
    approval_set_hash: &str,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let proposal = reservation.proposal();
    let body = &proposal.body;
    let proposal_json =
        canonical_json_bytes(proposal).map_err(|error| invariant(error.to_string()))?;
    let exact: bool = transaction
        .query_row(
            "SELECT COUNT(*) = 1 FROM threshold_approval_proposals
         WHERE operation_id = ?1 AND proposal_id = ?2 AND request_id = ?3
           AND governed_intent_hash = ?4 AND subject_fingerprint = ?5
           AND authorizing_capability_digest = ?6 AND policy_hash = ?7
           AND threshold = ?8 AND eligible_set_digest = ?9
           AND proposal_created_at = ?10 AND proposal_deadline = ?11
           AND proposal_hash = ?12 AND approval_set_hash = ?13 AND proposal_json = ?14
           AND state = 'reserved' AND reserved_at_unix_ms <= ?15
           AND updated_at_unix_ms = reserved_at_unix_ms",
            params![
                operation.binding().operation_id().as_str(),
                body.proposal_id,
                body.request_id,
                body.governed_intent_hash,
                body.subject.to_hex(),
                body.authorizing_capability_digest,
                body.policy_hash,
                i64::from(body.threshold),
                body.eligible_set_digest,
                sqlite_i64(body.proposal_created_at, "proposal_created_at")?,
                sqlite_i64(body.proposal_deadline, "proposal_deadline")?,
                proposal_hash,
                approval_set_hash,
                proposal_json,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(invariant(
            "threshold replay lost its exact durable proposal reservation",
        ));
    }
    let token_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM threshold_approval_tokens WHERE proposal_id = ?1",
            [&body.proposal_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if usize::try_from(token_count).ok() != Some(reservation.tokens().len()) {
        return Err(invariant(
            "threshold replay changed its durable token inventory",
        ));
    }
    for token in reservation.tokens() {
        let token_json =
            canonical_json_bytes(token).map_err(|error| invariant(error.to_string()))?;
        let digest = token
            .artifact_digest()
            .map_err(|error| invariant(error.to_string()))?;
        let exact: bool = transaction
            .query_row(
                "SELECT COUNT(*) = 1 FROM threshold_approval_tokens
             WHERE proposal_id = ?1 AND token_id = ?2 AND approver_fingerprint = ?3
               AND canonical_token_digest = ?4 AND token_json = ?5",
                params![
                    body.proposal_id,
                    token.id,
                    token.approver.to_hex(),
                    digest,
                    token_json
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !exact {
            return Err(invariant(
                "threshold replay lost its exact durable approval token",
            ));
        }
    }
    Ok(())
}
