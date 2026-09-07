//! Revalidate operation-owned approval evidence at the nonce capture boundary.

use super::*;
use chio_core::capability::governance::{
    GovernedApprovalToken, ThresholdApprovalProposal, VerifiedApprovalSetBody,
};
use chio_kernel::ThresholdApprovalReplayReservationV1;

pub(in crate::admission_operation_store) fn verify_nonce_capture_approval(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if !operation.binding().participant_requirements().approval {
        return Ok(());
    }
    let Some(proposal) = load_retained_proposal(transaction, operation)? else {
        return Err(invariant(
            "nonce capture requires bounded durable threshold approval evidence",
        ));
    };
    let maximum = chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS;
    let mut statement = transaction
        .prepare(
            "SELECT CASE WHEN length(token_json) BETWEEN 1 AND 262144 THEN token_json END
         FROM threshold_approval_tokens WHERE proposal_id = ?1
         ORDER BY canonical_token_digest LIMIT ?2",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            proposal.body.proposal_id,
            i64::try_from(maximum + 1).map_err(|_| invariant("threshold token bound overflow"))?
        ])
        .map_err(sqlite_error)?;
    let mut tokens = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        if tokens.len() == maximum {
            return Err(invariant(
                "nonce capture approval token inventory exceeds its bound",
            ));
        }
        let bytes: Option<Vec<u8>> = row.get(0).map_err(sqlite_error)?;
        let bytes = bytes
            .ok_or_else(|| invariant("nonce capture approval token exceeds its storage bound"))?;
        let token: GovernedApprovalToken =
            serde_json::from_slice(&bytes).map_err(|error| invariant(error.to_string()))?;
        if canonical_json_bytes(&token).map_err(|error| invariant(error.to_string()))? != bytes {
            return Err(invariant("nonce capture approval token is not canonical"));
        }
        tokens.push(token);
    }
    let token_digests = tokens
        .iter()
        .map(GovernedApprovalToken::artifact_digest)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invariant(error.to_string()))?;
    let set = VerifiedApprovalSetBody::new(token_digests, &proposal)
        .map_err(|error| invariant(error.to_string()))?;
    let reservation = ThresholdApprovalReplayReservationV1::new(proposal, tokens, set)?;
    let proposal_hash = reservation
        .proposal()
        .artifact_digest()
        .map_err(|error| invariant(error.to_string()))?;
    let set_hash = reservation
        .verified_set()
        .approval_set_hash()
        .map_err(|error| invariant(error.to_string()))?;
    if operation
        .threshold_proposal_hash()
        .map(AdmissionDigest::as_str)
        != Some(proposal_hash.as_str())
        || operation.approval_set_hash().map(AdmissionDigest::as_str) != Some(set_hash.as_str())
        || operation.binding().request_id().as_str() != reservation.proposal().body.request_id
        || operation
            .to_persisted()
            .binding
            .authorization_capability_hash
            .as_str()
            != reservation.proposal().body.authorizing_capability_digest
        || operation.binding().policy_hash().as_str() != reservation.proposal().body.policy_hash
    {
        return Err(invariant(
            "nonce capture approval changed its operation binding",
        ));
    }
    qualification::verify_window(&reservation, now)?;
    qualification::verify_exact_replay(
        transaction,
        operation,
        &reservation,
        &proposal_hash,
        &set_hash,
        now,
    )
}

/// The bounded, canonical threshold proposal retained for an operation.
fn load_retained_proposal(
    connection: &rusqlite::Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<ThresholdApprovalProposal>, AdmissionOperationStoreError> {
    let proposal_bytes: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(proposal_json) BETWEEN 1 AND 262144 THEN proposal_json END
         FROM threshold_approval_proposals WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(Some(proposal_bytes)) = proposal_bytes else {
        return Ok(None);
    };
    let proposal: ThresholdApprovalProposal =
        serde_json::from_slice(&proposal_bytes).map_err(|error| invariant(error.to_string()))?;
    if canonical_json_bytes(&proposal).map_err(|error| invariant(error.to_string()))?
        != proposal_bytes
    {
        return Err(invariant("nonce capture proposal is not canonical"));
    }
    Ok(Some(proposal))
}

/// The time at which an operation-bound nonce is verified for liveness. An
/// operation that parked for cumulative approval bound its nonce when the
/// kernel minted the retained proposal, so its nonce is verified at that
/// creation time rather than at the later reservation, capture or replay;
/// every other operation, and an issuance recorded before any proposal
/// exists, verifies at the recorded time.
pub(in crate::admission_operation_store) fn nonce_verification_time_unix_ms(
    connection: &rusqlite::Connection,
    operation: &AdmissionOperationV1,
    recorded_at_unix_ms: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    if !operation.binding().participant_requirements().approval {
        return Ok(recorded_at_unix_ms);
    }
    let Some(proposal) = load_retained_proposal(connection, operation)? else {
        return Ok(recorded_at_unix_ms);
    };
    if proposal.body.request_id != operation.binding().request_id().as_str() {
        return Err(invariant(
            "retained approval proposal does not bind this operation",
        ));
    }
    let created_at_unix_ms = proposal
        .body
        .proposal_created_at
        .checked_mul(1_000)
        .ok_or_else(|| invariant("approval proposal creation time overflows"))?;
    if created_at_unix_ms > recorded_at_unix_ms {
        return Err(invariant(
            "approval proposal was created after its nonce was recorded",
        ));
    }
    Ok(created_at_unix_ms)
}
