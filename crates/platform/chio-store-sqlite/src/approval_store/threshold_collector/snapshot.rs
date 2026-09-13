//! Reconcile the aggregate and indexed records inside the caller's transaction.

use super::{
    collector_error, collector_state_name, decode_collector, encode_collector,
    ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError,
};
use rusqlite::{params, Connection};

fn inconsistent() -> ThresholdApprovalCollectorStoreError {
    ThresholdApprovalCollectorStoreError::Serialization(
        "threshold approval persisted records are inconsistent".to_string(),
    )
}

pub(super) fn load_collector(
    connection: &Connection,
    proposal_id: &str,
) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError> {
    let mut statement = connection
        .prepare("SELECT * FROM chio_threshold_approval_collectors WHERE proposal_id = ?1")
        .map_err(collector_error)?;
    let mut rows = statement.query([proposal_id]).map_err(collector_error)?;
    let Some(row) = rows.next().map_err(collector_error)? else {
        return Ok(None);
    };
    let record_bytes: Vec<u8> = row.get("record_json").map_err(collector_error)?;
    let record = decode_collector(&record_bytes)?;
    let body = &record.proposal.body;
    if body.proposal_id != proposal_id
        || row
            .get::<_, String>("request_id")
            .map_err(collector_error)?
            != body.request_id
        || row
            .get::<_, String>("governed_intent_hash")
            .map_err(collector_error)?
            != body.governed_intent_hash
        || row
            .get::<_, String>("subject_fingerprint")
            .map_err(collector_error)?
            != body.subject.to_hex()
        || row
            .get::<_, String>("authorizing_capability_digest")
            .map_err(collector_error)?
            != body.authorizing_capability_digest
        || row
            .get::<_, String>("policy_hash")
            .map_err(collector_error)?
            != body.policy_hash
        || row.get::<_, u32>("threshold").map_err(collector_error)? != body.threshold
        || row
            .get::<_, String>("eligible_set_digest")
            .map_err(collector_error)?
            != body.eligible_set_digest
        || unsigned_column(row, "proposal_created_at")? != body.proposal_created_at
        || unsigned_column(row, "proposal_deadline")? != body.proposal_deadline
        || row
            .get::<_, Option<String>>("submitter_fingerprint")
            .map_err(collector_error)?
            != record.submitter.as_ref().map(|key| key.to_hex())
        || row
            .get::<_, i64>("require_submitter_separation")
            .map_err(collector_error)?
            != i64::from(record.require_submitter_separation)
        || row.get::<_, String>("state").map_err(collector_error)?
            != collector_state_name(record.state)
        || unsigned_column(row, "version")? != record.version
        || unsigned_column(row, "updated_at")? != record.updated_at
        || row
            .get::<_, Vec<u8>>("proposal_json")
            .map_err(collector_error)?
            != encode_collector(&record.proposal)?
        || row
            .get::<_, Vec<u8>>("requirement_json")
            .map_err(collector_error)?
            != encode_collector(&record.requirement)?
        || record_bytes != encode_collector(&record)?
    {
        return Err(inconsistent());
    }
    validate_votes(connection, &record)?;
    Ok(Some(record))
}

fn validate_votes(
    connection: &Connection,
    record: &ThresholdApprovalCollectorProposal,
) -> Result<(), ThresholdApprovalCollectorStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT token_id, approver_fingerprint, canonical_token_digest, token_json, received_at
         FROM chio_threshold_approval_collector_votes WHERE proposal_id = ?1 ORDER BY token_id",
        )
        .map_err(collector_error)?;
    let mut rows = statement
        .query(params![record.proposal.body.proposal_id])
        .map_err(collector_error)?;
    let mut expected = record.tokens.iter().collect::<Vec<_>>();
    expected.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    for token in expected {
        let row = rows
            .next()
            .map_err(collector_error)?
            .ok_or_else(inconsistent)?;
        let received_at = unsigned_column(row, "received_at")?;
        if row.get::<_, String>("token_id").map_err(collector_error)? != token.id
            || row
                .get::<_, String>("approver_fingerprint")
                .map_err(collector_error)?
                != token.approver.to_hex()
            || row
                .get::<_, String>("canonical_token_digest")
                .map_err(collector_error)?
                != token.artifact_digest().map_err(collector_error)?
            || row
                .get::<_, Vec<u8>>("token_json")
                .map_err(collector_error)?
                != encode_collector(token)?
            || !token.is_valid_at(received_at)
            || received_at > record.updated_at
            || received_at < record.proposal.body.proposal_created_at
            || received_at >= record.proposal.body.proposal_deadline
        {
            return Err(inconsistent());
        }
    }
    if rows.next().map_err(collector_error)?.is_some() {
        return Err(inconsistent());
    }
    Ok(())
}

fn unsigned_column(
    row: &rusqlite::Row<'_>,
    name: &str,
) -> Result<u64, ThresholdApprovalCollectorStoreError> {
    let value: i64 = row.get(name).map_err(collector_error)?;
    u64::try_from(value).map_err(|_| inconsistent())
}
