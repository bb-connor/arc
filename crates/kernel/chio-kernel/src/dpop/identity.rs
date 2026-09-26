//! Bounded replay identities and conservative retained-string accounting.

use super::KernelError;

/// Maximum UTF-8 byte length of one nonce, capability or reservation identity.
pub const MAX_DPOP_REPLAY_IDENTITY_PART_BYTES: usize = 4096;
/// Default aggregate retained identity budget, separate from marker capacity.
pub const DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY: usize = 16 * 1024 * 1024;

/// Validate borrowed replay keys before canonicalization, cloning or mutation.
/// This is not replay admission and does not reserve any capacity. Identity
/// text is never trimmed, truncated, normalized or echoed in errors.
pub fn validate_dpop_replay_identity(nonce: &str, capability_id: &str) -> Result<(), KernelError> {
    validate_part(nonce)?;
    validate_part(capability_id)
}

pub(super) fn validate_part(value: &str) -> Result<(), KernelError> {
    if value.len() > MAX_DPOP_REPLAY_IDENTITY_PART_BYTES {
        return Err(KernelError::DpopVerificationFailed(
            "replay identity exceeds the 4096-byte limit".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn retained_bytes(
    nonce: &str,
    capability_id: &str,
    owner: Option<&str>,
) -> Result<usize, KernelError> {
    // Charge two capability copies per marker to cover the key and the
    // per-capability count map. Shared count keys only reduce actual usage.
    nonce
        .len()
        .checked_add(capability_id.len())
        .and_then(|bytes| bytes.checked_add(capability_id.len()))
        .and_then(|bytes| bytes.checked_add(owner.map_or(0, str::len)))
        .ok_or_else(|| {
            KernelError::DpopVerificationFailed("replay identity byte count overflow".to_owned())
        })
}

pub(super) fn byte_budget_error() -> KernelError {
    KernelError::DpopVerificationFailed(
        "nonce store identity byte capacity exhausted; denying replay admission".to_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
