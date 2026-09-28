use super::*;

fn reading(unix: u64, monotonic_ms: u64) -> ClockReading {
    ClockReading::new(
        UnixMillis::new(unix),
        MonotonicInstant::from_nanos(monotonic_ms * 1_000_000),
    )
}

#[test]
fn clock_fence_refuses_regression_without_replacing_the_high_water() {
    let mut fence = ClockFence::default();
    assert_eq!(fence.observe(reading(100, 20)), Ok(reading(100, 20)));
    assert_eq!(
        fence.observe(reading(99, 21)),
        Err(ClockError::WallClockRegression)
    );
    assert_eq!(
        fence.observe(reading(101, 19)),
        Err(ClockError::MonotonicRegression)
    );
    assert_eq!(fence.observe(reading(100, 20)), Ok(reading(100, 20)));
}

#[test]
fn retries_cannot_extend_authority_when_wall_time_stops() -> Result<(), ClockError> {
    let mut deadline =
        AuthorityDeadline::new(UnixMillis::new(90), UnixMillis::new(120), reading(100, 0))?;
    assert_eq!(
        deadline.remaining(reading(100, 15))?,
        Duration::from_millis(5)
    );
    assert_eq!(
        deadline.remaining(reading(100, 20)),
        Err(ClockError::Expired)
    );
    Ok(())
}

#[test]
fn authority_expiry_and_skew_boundaries_are_exact() -> Result<(), ClockError> {
    assert_eq!(
        validate_future_skew(UnixMillis::new(110), UnixMillis::new(100), 10),
        Ok(())
    );
    assert_eq!(
        validate_future_skew(UnixMillis::new(111), UnixMillis::new(100), 10),
        Err(ClockError::NotYetValid)
    );
    assert_eq!(
        validate_future_skew(UnixMillis::new(u64::MAX), UnixMillis::new(u64::MAX), 1),
        Err(ClockError::Overflow)
    );
    let mut deadline =
        AuthorityDeadline::new(UnixMillis::new(100), UnixMillis::new(120), reading(100, 0))?;
    assert_eq!(
        deadline.remaining(reading(99, 1)),
        Err(ClockError::WallClockRegression)
    );
    assert_eq!(
        deadline.remaining(reading(120, 1)),
        Err(ClockError::Expired)
    );
    Ok(())
}

#[test]
fn conversions_never_wrap_or_substitute_epoch_zero() {
    assert_eq!(FixedClock::new(u64::MAX).read(), Err(ClockError::Overflow));
    assert_eq!(
        UnixMillis::new(u64::MAX).checked_add(1),
        Err(ClockError::Overflow)
    );
    assert_eq!(
        MonotonicInstant::from_nanos(u64::MAX).checked_add(Duration::from_nanos(1)),
        Err(ClockError::Overflow)
    );
}
