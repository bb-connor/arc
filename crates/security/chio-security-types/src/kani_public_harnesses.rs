use crate::clock::*;

#[kani::proof]
fn clock_fence_preserves_last_success_on_regression() {
    let first = ClockReading::new(
        UnixMillis::new(kani::any()),
        MonotonicInstant::from_nanos(kani::any()),
    );
    let next = ClockReading::new(
        UnixMillis::new(kani::any()),
        MonotonicInstant::from_nanos(kani::any()),
    );
    let mut fence = ClockFence::default();
    assert_eq!(fence.observe(first), Ok(first));
    let result = fence.observe(next);
    if next.unix_millis() < first.unix_millis() || next.monotonic() < first.monotonic() {
        assert_eq!(
            result,
            Err(if next.unix_millis() < first.unix_millis() {
                ClockError::WallClockRegression
            } else {
                ClockError::MonotonicRegression
            })
        );
        assert_eq!(fence.observe(first), Ok(first));
    } else {
        assert_eq!(result, Ok(next));
        assert_eq!(fence.observe(next), Ok(next));
    }
}

#[kani::proof]
fn authority_deadline_never_extends_on_retry() {
    let now = ClockReading::new(
        UnixMillis::new(kani::any()),
        MonotonicInstant::from_nanos(kani::any()),
    );
    let timeout: u64 = kani::any();
    if let Ok(mut deadline) = AuthorityDeadline::for_timeout_ms(now, timeout) {
        let sample = ClockReading::new(
            UnixMillis::new(kani::any()),
            MonotonicInstant::from_nanos(kani::any()),
        );
        let fixed = deadline.monotonic_deadline();
        if let Ok(remaining) = deadline.remaining_nanos(sample) {
            assert!(sample.unix_millis() >= now.unix_millis());
            assert!(sample.monotonic() >= now.monotonic());
            assert!(remaining > 0);
            assert_eq!(deadline.monotonic_deadline(), fixed);
            assert!(sample.unix_millis() < UnixMillis::new(now.unix_millis().get() + timeout));
            assert!(sample.monotonic() < fixed);
        }
        assert_eq!(deadline.monotonic_deadline(), fixed);
    }
}

#[kani::proof]
fn future_skew_uses_checked_full_width_arithmetic() {
    let now: u64 = kani::any();
    let observed: u64 = kani::any();
    let skew: u64 = kani::any();
    let result = validate_future_skew(UnixMillis::new(observed), UnixMillis::new(now), skew);
    let upper = u128::from(now) + u128::from(skew);
    if upper > u128::from(u64::MAX) {
        assert_eq!(result, Err(ClockError::Overflow));
    } else {
        assert_eq!(result.is_ok(), u128::from(observed) <= upper);
    }
}

#[kani::proof]
fn response_terminal_states_and_clean_rollback_are_closed() {
    use crate::response_state::{
        is_legal_response_transition, rollback_effect_is_restored, ResponseState::*,
    };
    let states = [
        Planned,
        AwaitingApproval,
        Applying,
        Active,
        ApplyPartial,
        Expiring,
        RollingBack,
        RollbackPartial,
        Cancelled,
        Expired,
        Failed,
        Lifted,
    ];
    let from: usize = kani::any();
    let to: usize = kani::any();
    kani::assume(from < states.len() && to < states.len());
    if states[from].is_terminal() {
        assert!(!is_legal_response_transition(states[from], states[to]));
    }
    if states[to] == Lifted && is_legal_response_transition(states[from], states[to]) {
        assert_eq!(states[from], RollingBack);
    }
    let reversible: bool = kani::any();
    let applied: bool = kani::any();
    let restored: bool = kani::any();
    if reversible && applied {
        assert_eq!(
            rollback_effect_is_restored(reversible, applied, restored),
            restored
        );
    }
}
