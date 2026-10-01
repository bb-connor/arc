use chio_core::{canonical_json_bytes, sha256};
use chio_kernel::ActiveResponseExecutorError;
use chio_security_types::ports::{Digest32, RecordId, ResponsePlanRecord};
use chio_security_types::{ResponseMutationRecord, ResponseSnapshot, ResponseState};
use serde::Serialize;

const RECOVERY_ID_DOMAIN: &[u8] = b"chio.active-response-recovery.v1\0";

pub(super) fn has_durable_execution_proof(snapshot: &ResponseSnapshot) -> bool {
    snapshot.mutations.as_slice().iter().any(|mutation| {
        matches!(
            mutation,
            ResponseMutationRecord::Transition(transition)
                if transition.to_state == ResponseState::Active
        )
    }) || matches!(
        snapshot.state,
        ResponseState::Failed | ResponseState::Lifted
    )
}

pub(super) fn decode_lower_hex_digest(value: &str) -> Option<Digest32> {
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || bytes
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = hex_nibble(pair[0])?.checked_mul(16)? + hex_nibble(pair[1])?;
    }
    Some(Digest32::new(decoded))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn digest_is_zero(digest: &Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

pub(super) fn valid_prefixed_digest_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(decode_lower_hex_digest)
        .is_some_and(|digest| !digest_is_zero(&digest))
}

pub(super) fn recovery_id(
    dispatch_id: &RecordId,
    current: &ResponsePlanRecord,
    now_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
) -> Result<RecordId, ActiveResponseExecutorError> {
    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryBody<'a> {
        dispatch_id: &'a RecordId,
        action_id: &'a chio_security_types::ports::ActionId,
        response_generation: u64,
        response_body_hash: Digest32,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    }

    let canonical = canonical_json_bytes(&RecoveryBody {
        dispatch_id,
        action_id: &current.action_id,
        response_generation: current.generation,
        response_body_hash: current.body_hash,
        now_unix_ms,
        lease_expires_at_unix_ms,
    })
    .map_err(|error| {
        ActiveResponseExecutorError::OutcomeUnknown(format!(
            "active-response recovery id canonicalization failed: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(RECOVERY_ID_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(RECOVERY_ID_DOMAIN);
    preimage.extend_from_slice(&canonical);
    RecordId::new(format!(
        "active_response_recovery_{}",
        sha256(&preimage).to_hex()
    ))
    .map_err(|_| {
        ActiveResponseExecutorError::OutcomeUnknown(
            "active-response recovery id is invalid".to_string(),
        )
    })
}
