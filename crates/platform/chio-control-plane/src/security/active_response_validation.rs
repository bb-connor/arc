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

/// Decodes exactly 64 lowercase hexadecimal characters into a digest.
///
/// The all-zero digest decodes like any other value; a caller that requires a
/// nonzero digest must reject it explicitly.
pub(super) fn decode_lower_hex_digest(value: &str) -> Option<Digest32> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded).ok()?;
    Some(Digest32::new(decoded))
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

    fn repeated(pattern: [u8; 8]) -> Digest32 {
        let mut bytes = [0_u8; 32];
        for chunk in bytes.chunks_exact_mut(8) {
            chunk.copy_from_slice(&pattern);
        }
        Digest32::new(bytes)
    }

    fn non_canonical_digest_texts() -> Vec<String> {
        let valid = "0123456789abcdef".repeat(4);
        vec![
            String::new(),
            valid[..62].to_string(),
            valid[..63].to_string(),
            format!("{valid}0"),
            format!("{valid}00"),
            valid.to_ascii_uppercase(),
            format!("A{}", &valid[1..]),
            format!("{}F", &valid[..63]),
            format!("0x{}", &valid[2..]),
            format!("0X{}", &valid[2..]),
            format!("0x{valid}"),
            format!(" {}", &valid[1..]),
            format!("{} ", &valid[..63]),
            format!(" {valid}"),
            format!("{valid}\n"),
            format!("g{}", &valid[1..]),
            "z".repeat(64),
            format!("+{}", &valid[1..]),
            format!("\u{e9}{}", &valid[2..]),
        ]
    }

    #[test]
    fn lower_hex_digest_decodes_every_nibble_in_both_positions() {
        assert_eq!(
            decode_lower_hex_digest(&"0123456789abcdef".repeat(4)),
            Some(repeated([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]))
        );
        assert_eq!(
            decode_lower_hex_digest(&"1032547698badcfe".repeat(4)),
            Some(repeated([0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe]))
        );
        assert_eq!(
            decode_lower_hex_digest(&"ff".repeat(32)),
            Some(Digest32::new([0xff; 32]))
        );
    }

    #[test]
    fn lower_hex_digest_returns_the_zero_digest_to_the_caller() {
        assert_eq!(
            decode_lower_hex_digest(&"0".repeat(64)),
            Some(Digest32::new([0; 32]))
        );
    }

    #[test]
    fn lower_hex_digest_rejects_every_non_canonical_text() {
        for text in non_canonical_digest_texts() {
            assert_eq!(decode_lower_hex_digest(&text), None, "accepted {text:?}");
        }
    }

    #[test]
    fn lower_hex_digest_accepts_exactly_the_canonical_hash_text() {
        let mut texts = non_canonical_digest_texts();
        texts.extend([
            "0123456789abcdef".repeat(4),
            "0".repeat(64),
            "ff".repeat(32),
        ]);
        for text in texts {
            let canonical_hash = chio_core::Hash::from_hex(&text)
                .ok()
                .filter(|hash| hash.to_hex() == text)
                .map(|hash| Digest32::new(*hash.as_bytes()));
            assert_eq!(
                decode_lower_hex_digest(&text),
                canonical_hash,
                "disagreed on {text:?}"
            );
        }
    }

    #[test]
    fn prefixed_digest_id_requires_a_nonzero_canonical_digest() {
        let prefix = "active_response_dispatch_";
        let valid = "0123456789abcdef".repeat(4);
        assert!(valid_prefixed_digest_id(
            &format!("{prefix}{valid}"),
            prefix
        ));
        assert!(!valid_prefixed_digest_id(
            &format!("{prefix}{}", "0".repeat(64)),
            prefix
        ));
        assert!(!valid_prefixed_digest_id(
            &format!("{prefix}{}", valid.to_ascii_uppercase()),
            prefix
        ));
        assert!(!valid_prefixed_digest_id(
            &format!("{prefix}0x{}", &valid[2..]),
            prefix
        ));
        assert!(!valid_prefixed_digest_id(&valid, prefix));
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
