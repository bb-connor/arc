use super::{
    canonical_json_bytes, validate_digest, BrokerError, BrokerExecuteRequest, Digest, Result,
    Sha256, ATTEMPT_OPERATION_GATE_COUNT,
};

pub(super) const REQUEST_DIGEST_DOMAIN: &[u8] = b"chio.broker-canonical-request.v1\0";
pub(super) const FAILURE_RECEIPT_REQUEST_DOMAIN: &[u8] =
    b"chio.broker-failure-terminal-request.v1\0";

pub(super) fn attempt_operation_gate_index(digest: &str) -> Result<usize> {
    validate_digest(digest, "attempt operation gate digest")?;
    let prefix = digest.get(..2).ok_or_else(|| {
        BrokerError::Invariant("attempt operation gate digest lost its prefix".to_string())
    })?;
    let prefix = usize::from(u8::from_str_radix(prefix, 16).map_err(|error| {
        BrokerError::Invariant(format!("attempt operation gate prefix is invalid: {error}"))
    })?);
    Ok(prefix % ATTEMPT_OPERATION_GATE_COUNT)
}

pub fn broker_request_digest(request: &BrokerExecuteRequest) -> Result<String> {
    let canonical = canonical_json_bytes(&request.request)
        .map_err(|error| BrokerError::Invariant(format!("request digest failed: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}
