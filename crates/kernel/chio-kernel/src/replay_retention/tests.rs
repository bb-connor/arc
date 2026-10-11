use super::*;
use chio_security_types::clock::Clock;
use std::sync::Mutex;

pub(crate) struct TestClock(Mutex<Result<ClockReading, ClockError>>);
impl TestClock {
    pub(crate) fn new(seconds: u64) -> Self {
        Self(Mutex::new(Ok(reading(seconds, 0))))
    }
    pub(crate) fn set(&self, wall_seconds: u64, monotonic_seconds: u64) {
        *self.0.lock().unwrap() = Ok(reading(wall_seconds, monotonic_seconds));
    }
    pub(crate) fn fail(&self) {
        *self.0.lock().unwrap() = Err(ClockError::Unavailable);
    }
}
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}
fn reading(wall: u64, mono: u64) -> ClockReading {
    ClockReading::new(
        UnixMillis::from_secs(wall).unwrap(),
        MonotonicInstant::from_nanos(mono * 1_000_000_000),
    )
}
#[test]
fn retention_requires_both_original_deadlines() {
    let retention = ReplayHorizon::Until(110).project(reading(100, 0));
    assert!(!retention.is_expired_at(reading(120, 9)));
    assert!(!retention.is_expired_at(reading(109, 20)));
    assert!(retention.is_expired_at(reading(110, 10)));
}
#[test]
fn inclusive_horizon_and_unrepresentable_retention_never_shorten_custody() {
    let retention = ReplayHorizon::Through(110).project(reading(100, 0));
    assert!(!retention.is_expired_at(reading(110, 10)));
    assert!(retention.is_expired_at(reading(111, 11)));
    for horizon in [
        ReplayHorizon::Through(u64::MAX),
        ReplayHorizon::Until(u64::MAX),
        ReplayHorizon::Local(Duration::MAX),
    ] {
        assert!(!horizon
            .project(reading(100, 0))
            .is_expired_at(reading(200, 100)));
    }
}
#[test]
fn regression_refuses_without_advancing_pruning_horizon() {
    let mut clock = ReplayClock::default();
    clock.observe("test", reading(100, 10)).unwrap();
    assert!(matches!(
        clock.observe("test", reading(99, 11)),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    assert!(matches!(
        clock.observe("test", reading(101, 9)),
        Err(KernelError::Clock(ClockError::MonotonicRegression))
    ));
    assert_eq!(clock.high_water().unwrap(), reading(100, 10));
}
#[test]
fn stable_suspend_requires_two_samples_and_preserves_original_monotonic_cap() {
    let mut clock = ReplayClock::default();
    clock.observe("test", reading(100, 0)).unwrap();
    let retention = ReplayHorizon::Until(200).project(reading(100, 0));
    assert!(matches!(
        clock.observe("test", reading(3700, 1)),
        Err(KernelError::ReplayClockAnomaly { .. })
    ));
    assert_eq!(clock.high_water().unwrap(), reading(100, 0));
    assert!(matches!(
        clock.observe("test", reading(3700, 1)),
        Err(KernelError::ReplayClockAnomaly { .. })
    ));
    let confirmed = clock.observe("test", reading(3701, 2)).unwrap();
    assert!(!retention.is_expired_at(confirmed));
    assert!(retention.is_expired_at(reading(3800, 101)));
}
#[test]
fn inconsistent_jumps_cannot_confirm_a_suspend() {
    let mut clock = ReplayClock::default();
    clock.observe("test", reading(100, 0)).unwrap();
    for (wall, mono) in [(3700, 1), (7200, 2), (10000, 3)] {
        assert!(matches!(
            clock.observe("test", reading(wall, mono)),
            Err(KernelError::ReplayClockAnomaly { .. })
        ));
        assert_eq!(clock.high_water().unwrap(), reading(100, 0));
    }
    assert_eq!(
        clock.observe("test", reading(104, 4)).unwrap(),
        reading(104, 4)
    );
}
