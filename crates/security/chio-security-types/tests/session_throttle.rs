#![cfg(feature = "std")]

use chio_security_types::ports::{
    empty_session_throttle_snapshot, predict_session_throttle_apply,
    predict_session_throttle_remove, session_throttle_installed_version_hash,
    session_throttle_version_hash, session_throttle_window_identity, Digest32, EffectId, SessionId,
    SessionThrottleContribution, SessionThrottleKey, SessionThrottleLimits, TenantId,
    SESSION_THROTTLE_MAX_INVOCATIONS, SESSION_THROTTLE_MAX_WINDOW_MS,
};

fn key() -> SessionThrottleKey {
    SessionThrottleKey {
        tenant_id: TenantId::new("tenant-throttle")
            .unwrap_or_else(|error| panic!("tenant id: {error}")),
        session_id: SessionId::new("session-throttle")
            .unwrap_or_else(|error| panic!("session id: {error}")),
    }
}

fn contribution(effect: &str, window_ms: u64, max_invocations: u32) -> SessionThrottleContribution {
    SessionThrottleContribution {
        effect_id: EffectId::new(effect).unwrap_or_else(|error| panic!("effect id: {error}")),
        limits: SessionThrottleLimits {
            window_ms,
            max_invocations,
        },
        contribution_hash: Digest32::new([7_u8; 32]),
        expires_at_unix_ms: 50_000,
    }
}

#[test]
fn limits_are_nonzero_and_bounded() {
    for invalid in [
        SessionThrottleLimits {
            window_ms: 0,
            max_invocations: 1,
        },
        SessionThrottleLimits {
            window_ms: SESSION_THROTTLE_MAX_WINDOW_MS.saturating_add(1),
            max_invocations: 1,
        },
        SessionThrottleLimits {
            window_ms: 1,
            max_invocations: 0,
        },
        SessionThrottleLimits {
            window_ms: 1,
            max_invocations: SESSION_THROTTLE_MAX_INVOCATIONS.saturating_add(1),
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    SessionThrottleLimits {
        window_ms: SESSION_THROTTLE_MAX_WINDOW_MS,
        max_invocations: SESSION_THROTTLE_MAX_INVOCATIONS,
    }
    .validate()
    .unwrap_or_else(|error| panic!("maximum throttle limits rejected: {error}"));
}

#[test]
fn window_identity_is_aligned_deterministic_and_effect_scoped() {
    let key = key();
    let first = contribution("effect-a", 1_000, 3);
    let same = session_throttle_window_identity(&key, &first.effect_id, first.limits, 10_999)
        .unwrap_or_else(|error| panic!("first window identity: {error}"));
    let repeated = session_throttle_window_identity(&key, &first.effect_id, first.limits, 10_001)
        .unwrap_or_else(|error| panic!("repeated window identity: {error}"));
    let next = session_throttle_window_identity(&key, &first.effect_id, first.limits, 11_000)
        .unwrap_or_else(|error| panic!("next window identity: {error}"));
    let other = contribution("effect-b", 1_000, 3);
    let other = session_throttle_window_identity(&key, &other.effect_id, other.limits, 10_999)
        .unwrap_or_else(|error| panic!("other effect window identity: {error}"));
    assert_eq!(same, repeated);
    assert_eq!(same.window_start_unix_ms, 10_000);
    assert_eq!(same.window_end_unix_ms, 11_000);
    assert_ne!(same.window_id, next.window_id);
    assert_ne!(same.window_id, other.window_id);
}

#[test]
fn versions_bind_each_independent_contribution_and_out_of_order_removal() {
    let empty = empty_session_throttle_snapshot(key())
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let first = contribution("effect-a", 1_000, 2);
    let second = contribution("effect-b", 2_000, 3);
    let after_first = predict_session_throttle_apply(&empty, &first, 1)
        .unwrap_or_else(|error| panic!("first throttle apply: {error}"));
    let after_second = predict_session_throttle_apply(&after_first, &second, 2)
        .unwrap_or_else(|error| panic!("second throttle apply: {error}"));
    assert_eq!(
        after_second.contributions.as_slice(),
        &[first.clone(), second.clone()]
    );
    assert_ne!(
        session_throttle_version_hash(&after_first)
            .unwrap_or_else(|error| panic!("first snapshot version: {error}")),
        session_throttle_version_hash(&after_second)
            .unwrap_or_else(|error| panic!("second snapshot version: {error}"))
    );
    assert_ne!(
        session_throttle_installed_version_hash(&key(), &first)
            .unwrap_or_else(|error| panic!("first installed version: {error}")),
        session_throttle_installed_version_hash(&key(), &second)
            .unwrap_or_else(|error| panic!("second installed version: {error}"))
    );
    let remaining = predict_session_throttle_remove(&after_second, &first.effect_id, 3)
        .unwrap_or_else(|error| panic!("remove first contribution: {error}"));
    assert_eq!(remaining.contributions.as_slice(), &[second]);
}
