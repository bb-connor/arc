use chio_core_types::receipt::security::{
    active_defense_response_receipt_for_mutation, ActiveDefenseReceiptBody,
};
use chio_core_types::{canonical_json_bytes, Error};
use chio_security_types::ports::{CanonicalBody, ReceiptAppendRequest, RecordId};
use chio_security_types::ResponseSnapshot;

pub(crate) fn response_receipt_for_mutation(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
) -> Result<ActiveDefenseReceiptBody, Error> {
    active_defense_response_receipt_for_mutation(snapshot, mutation_index)
}

pub(crate) fn latest_response_receipt(
    snapshot: &ResponseSnapshot,
) -> Result<ActiveDefenseReceiptBody, Error> {
    let index = snapshot
        .mutations
        .len()
        .checked_sub(1)
        .ok_or_else(|| receipt_error("response mutation log is empty"))?;
    response_receipt_for_mutation(snapshot, index)
}

pub(crate) fn receipt_append_request(
    body: &ActiveDefenseReceiptBody,
) -> Result<ReceiptAppendRequest, Error> {
    body.validate()
        .map_err(|error| receipt_error(&error.to_string()))?;
    let canonical = canonical_json_bytes(body)?;
    Ok(ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())
            .map_err(|error| receipt_error(&error.to_string()))?,
        evidence_id: body.evidence_id()?,
        canonical_body: CanonicalBody::new(canonical)
            .map_err(|error| receipt_error(&error.to_string()))?,
        body_hash: body.body_digest()?,
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
}

fn receipt_error(message: &str) -> Error {
    Error::CanonicalJson(message.to_owned())
}
