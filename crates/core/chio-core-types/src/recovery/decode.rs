use chio_security_types::recovery::{
    ContractError, MAX_RECOVERY_CONTAINER_ENTRIES, MAX_RECOVERY_DEPTH, MAX_RECOVERY_NODES,
    MAX_RECOVERY_STRING_BYTES, MAX_RECOVERY_WIRE_BYTES,
};
use serde::{de::DeserializeOwned, Serialize};

/// Callers can tighten protocol ceilings, never raise them. String accounting
/// includes encoded escape bytes so preflight requires no allocation at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDecodeLimits {
    pub(super) bytes: usize,
    pub(super) depth: usize,
    pub(super) nodes: usize,
    pub(super) string_bytes: usize,
    pub(super) container_entries: usize,
}
impl Default for RecoveryDecodeLimits {
    fn default() -> Self {
        Self {
            bytes: MAX_RECOVERY_WIRE_BYTES,
            depth: MAX_RECOVERY_DEPTH,
            nodes: MAX_RECOVERY_NODES,
            string_bytes: MAX_RECOVERY_STRING_BYTES,
            container_entries: MAX_RECOVERY_CONTAINER_ENTRIES,
        }
    }
}
impl RecoveryDecodeLimits {
    pub fn new(
        bytes: usize,
        depth: usize,
        nodes: usize,
        string_bytes: usize,
        container_entries: usize,
    ) -> Result<Self, ContractError> {
        let limits = Self {
            bytes,
            depth,
            nodes,
            string_bytes,
            container_entries,
        };
        let ceilings = Self::default();
        for (limit, ceiling) in [
            (bytes, ceilings.bytes),
            (depth, ceilings.depth),
            (nodes, ceilings.nodes),
            (string_bytes, ceilings.string_bytes),
            (container_entries, ceilings.container_entries),
        ] {
            if limit == 0 || limit > ceiling {
                return Err(ContractError::LimitExceeded);
            }
        }
        Ok(limits)
    }
}

/// Decode only closed, data-only contracts. Successful parsing does not verify
/// signatures, authority, profile enforcement, effect truth or audience access.
pub fn decode_contract<T: DeserializeOwned + Serialize>(input: &[u8]) -> Result<T, ContractError> {
    decode_contract_with_limits(input, RecoveryDecodeLimits::default())
}

pub fn decode_contract_with_limits<T: DeserializeOwned + Serialize>(
    input: &[u8],
    limits: RecoveryDecodeLimits,
) -> Result<T, ContractError> {
    // Preflight must run before the existing lossless parser builds a Value.
    super::preflight::check(input, limits)?;
    let text = core::str::from_utf8(input).map_err(|_| ContractError::Malformed)?;
    let value = crate::canonical::parse_signed_json(text).map_err(|_| ContractError::Malformed)?;
    let canonical = crate::canonical_json_bytes(&value).map_err(|_| ContractError::Malformed)?;
    if canonical != input {
        return Err(ContractError::NonCanonical);
    }
    let typed: T = serde_json::from_value(value).map_err(|_| ContractError::Malformed)?;
    // A typed decoder may not normalize or silently discard a signed field.
    if crate::canonical_json_bytes(&typed).map_err(|_| ContractError::Malformed)? != input {
        return Err(ContractError::NonCanonical);
    }
    Ok(typed)
}

/// Legacy capabilities have an established canonical signing body, independent
/// of whitespace in their exported envelope. Intake remains bounded, lossless
/// and closed before the kernel's full capability verifier evaluates authority.
pub fn decode_recovery_capability(
    input: &[u8],
) -> Result<crate::capability::token::CapabilityToken, ContractError> {
    super::preflight::check(input, RecoveryDecodeLimits::default())?;
    let text = core::str::from_utf8(input).map_err(|_| ContractError::Malformed)?;
    let value = crate::canonical::parse_signed_json(text).map_err(|_| ContractError::Malformed)?;
    let canonical = crate::canonical_json_bytes(&value).map_err(|_| ContractError::Malformed)?;
    let token = serde_json::from_value(value).map_err(|_| ContractError::Malformed)?;
    if crate::canonical_json_bytes(&token).map_err(|_| ContractError::Malformed)? != canonical {
        return Err(ContractError::Malformed);
    }
    Ok(token)
}
