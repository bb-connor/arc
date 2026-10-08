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
    for (target, [high, low]) in decoded.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *target = hex_nibble(*high)?.checked_mul(16)? + hex_nibble(*low)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::ports::{ActionId, CanonicalBody, TenantId};

    fn record_id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id {value}: {error}"))
    }

    #[test]
    fn recovery_id_golden_vector_is_exact() {
        let current = ResponsePlanRecord {
            tenant_id: TenantId::new("tenant-recovery-golden")
                .unwrap_or_else(|error| panic!("tenant id: {error}")),
            action_id: ActionId::new("action-recovery-golden")
                .unwrap_or_else(|error| panic!("action id: {error}")),
            generation: 7,
            state: record_id("active"),
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: Digest32::new([0x5a; 32]),
            due_at_unix_ms: None,
        };
        let mut preimage = RECOVERY_ID_DOMAIN.to_vec();
        preimage.extend_from_slice(
            br#"{"action_id":"action-recovery-golden","dispatch_id":"active_response_dispatch_golden","lease_expires_at_unix_ms":1700000030000,"now_unix_ms":1700000000000,"response_body_hash":[90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90],"response_generation":7}"#,
        );
        assert_eq!(
            sha256(&preimage).to_hex(),
            "dbb3ce3de3656650bc428544396b97b18e444b653cd986acdc8fe270b61e499c"
        );

        let id = recovery_id(
            &record_id("active_response_dispatch_golden"),
            &current,
            1_700_000_000_000,
            1_700_000_030_000,
        )
        .unwrap_or_else(|error| panic!("recovery id: {error}"));
        assert_eq!(
            id.as_str(),
            "active_response_recovery_dbb3ce3de3656650bc428544396b97b18e444b653cd986acdc8fe270b61e499c"
        );
    }
}
