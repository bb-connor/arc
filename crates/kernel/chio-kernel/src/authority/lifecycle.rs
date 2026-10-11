//! Live issuer authority is distinct from retained public signature history.
use super::{AuthoritySnapshot, AuthorityStoreError, AuthorityTrustedKeySnapshot};
use serde::{Deserialize, Serialize};

/// Conservative maximum overlap for newly rotated and legacy verification keys.
pub const DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorityKeyLifecycle {
    Active,
    VerificationOnly { issue_until: u64, verify_until: u64 },
    Retired { at: u64 },
    Revoked { at: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorityLifecycleChange {
    Rotate { verify_until: u64 },
    Retire { public_key_hex: String },
    Revoke { public_key_hex: String },
    Recover,
}

/// Legacy bytes stay unchanged; their trust window does not remain unbounded.
pub fn key_lifecycle(
    state: &AuthoritySnapshot,
    index: usize,
) -> Result<AuthorityKeyLifecycle, AuthorityStoreError> {
    let key = state
        .trusted_keys
        .get(index)
        .ok_or_else(|| refused("unknown issuer"))?;
    if let Some(lifecycle) = &key.lifecycle {
        return Ok(lifecycle.clone());
    }
    match state.trusted_keys.get(index + 1) {
        Some(successor) => Ok(AuthorityKeyLifecycle::VerificationOnly {
            issue_until: successor.activated_at,
            verify_until: successor
                .activated_at
                .checked_add(DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS)
                .ok_or_else(|| refused("issuer deadline overflow"))?,
        }),
        None => Ok(AuthorityKeyLifecycle::Active),
    }
}

pub fn issuer_is_live(
    state: &AuthoritySnapshot,
    index: usize,
    issued_at: Option<u64>,
    now: u64,
) -> Result<bool, AuthorityStoreError> {
    let key = state
        .trusted_keys
        .get(index)
        .ok_or_else(|| refused("unknown issuer"))?;
    if now < key.activated_at || issued_at.is_some_and(|at| at < key.activated_at || at > now) {
        return Ok(false);
    }
    Ok(match key_lifecycle(state, index)? {
        AuthorityKeyLifecycle::Active => true,
        // Tokens have whole-second issuance times. A same-second token may
        // precede rotation; the verification deadline remains exclusive.
        AuthorityKeyLifecycle::VerificationOnly {
            issue_until,
            verify_until,
        } => now < verify_until && issued_at.is_none_or(|at| at <= issue_until),
        AuthorityKeyLifecycle::Retired { .. } | AuthorityKeyLifecycle::Revoked { .. } => false,
    })
}

pub(super) fn validate_lifecycle(state: &AuthoritySnapshot) -> Result<(), AuthorityStoreError> {
    let explicit = state.trusted_keys.iter().any(|key| key.lifecycle.is_some());
    for (index, key) in state.trusted_keys.iter().enumerate() {
        if explicit && key.lifecycle.is_none() {
            return Err(refused("partially specified issuer lifecycle"));
        }
        let head = key.public_key_hex == state.public_key_hex;
        let valid = match key_lifecycle(state, index)? {
            AuthorityKeyLifecycle::Active => head,
            AuthorityKeyLifecycle::VerificationOnly {
                issue_until,
                verify_until,
            } => {
                !head
                    && key.activated_at <= issue_until
                    && issue_until <= state.rotated_at
                    && verify_until >= issue_until
                    && verify_until
                        <= issue_until
                            .checked_add(DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS)
                            .ok_or_else(|| refused("issuer deadline overflow"))?
            }
            AuthorityKeyLifecycle::Retired { at } | AuthorityKeyLifecycle::Revoked { at } => {
                !head && key.activated_at <= at && at <= state.rotated_at
            }
        };
        if !valid {
            return Err(refused("invalid issuer lifecycle"));
        }
    }
    Ok(())
}

/// Derive the entire next state; no caller-supplied history can add authority.
pub fn apply_lifecycle_change(
    previous: &AuthoritySnapshot,
    change: &AuthorityLifecycleChange,
    next_key: &str,
    at: u64,
) -> Result<AuthoritySnapshot, AuthorityStoreError> {
    super::replication::validate_state(previous)?;
    if at < previous.rotated_at {
        return Err(refused("authority lifecycle regresses time"));
    }
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or_else(|| refused("authority generation exhausted"))?;
    let mut next = previous.clone();
    for (index, key) in next.trusted_keys.iter_mut().enumerate() {
        key.lifecycle = Some(key_lifecycle(previous, index)?);
    }
    match change {
        AuthorityLifecycleChange::Rotate { .. } | AuthorityLifecycleChange::Recover => {
            if previous
                .trusted_keys
                .iter()
                .any(|key| key.public_key_hex == next_key)
            {
                return Err(refused("authority rotation reuses a key"));
            }
            match change {
                AuthorityLifecycleChange::Rotate { verify_until } => {
                    let maximum = at
                        .checked_add(DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS)
                        .ok_or_else(|| refused("issuer deadline overflow"))?;
                    if *verify_until < at || *verify_until > maximum {
                        return Err(refused("issuer verification deadline outside grace bound"));
                    }
                    let head = next
                        .trusted_keys
                        .last_mut()
                        .ok_or_else(|| refused("authority head missing"))?;
                    head.lifecycle = Some(AuthorityKeyLifecycle::VerificationOnly {
                        issue_until: at,
                        verify_until: *verify_until,
                    });
                }
                AuthorityLifecycleChange::Recover => {
                    for key in &mut next.trusted_keys {
                        key.lifecycle = Some(AuthorityKeyLifecycle::Revoked { at });
                    }
                }
                _ => return Err(refused("invalid successor operation")),
            }
            next.public_key_hex = next_key.into();
            next.trusted_keys.push(AuthorityTrustedKeySnapshot {
                public_key_hex: next_key.into(),
                generation,
                activated_at: at,
                lifecycle: Some(AuthorityKeyLifecycle::Active),
            });
        }
        AuthorityLifecycleChange::Retire { public_key_hex }
        | AuthorityLifecycleChange::Revoke { public_key_hex } => {
            if next_key != previous.public_key_hex || public_key_hex == &previous.public_key_hex {
                return Err(refused("head removal requires an atomic successor"));
            }
            let key = next
                .trusted_keys
                .iter_mut()
                .find(|key| &key.public_key_hex == public_key_hex)
                .ok_or_else(|| refused("unknown issuer"))?;
            if matches!(key.lifecycle, Some(AuthorityKeyLifecycle::Revoked { .. }))
                || (matches!(change, AuthorityLifecycleChange::Retire { .. })
                    && matches!(key.lifecycle, Some(AuthorityKeyLifecycle::Retired { .. })))
            {
                return Err(refused("issuer lifecycle is already terminal"));
            }
            key.lifecycle = Some(match change {
                AuthorityLifecycleChange::Retire { .. } => AuthorityKeyLifecycle::Retired { at },
                _ => AuthorityKeyLifecycle::Revoked { at },
            });
        }
    }
    next.generation = generation;
    next.rotated_at = at;
    super::replication::validate_state(&next)?;
    Ok(next)
}

fn refused(message: &str) -> AuthorityStoreError {
    AuthorityStoreError::Fence(message.into())
}
