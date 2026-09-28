#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use chio_security_types::clock::{ClockReading, UnixMillis};

pub(crate) struct ManualClock(Mutex<Result<ClockReading, ClockError>>);
impl ManualClock {
    pub(crate) fn new(seconds: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Ok(ClockReading::new(
            UnixMillis::from_secs(seconds).unwrap(),
            MonotonicInstant::from_nanos(0),
        )))))
    }
    pub(crate) fn set(&self, seconds: u64, monotonic_seconds: u64) {
        *self.0.lock().unwrap() = Ok(ClockReading::new(
            UnixMillis::from_secs(seconds).unwrap(),
            MonotonicInstant::from_nanos(monotonic_seconds.checked_mul(1_000_000_000).unwrap()),
        ));
    }
    pub(crate) fn fail(&self, error: ClockError) {
        *self.0.lock().unwrap() = Err(error);
    }
}
impl Clock for ManualClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}

/// Advance a shared clock at an exact read boundary without sleeping.
pub(crate) struct StepClock {
    source: Arc<ManualClock>,
    step: Mutex<Option<(usize, u64, u64)>>,
}
impl StepClock {
    pub(crate) fn new(seconds: u64) -> Arc<Self> {
        Arc::new(Self {
            source: ManualClock::new(seconds),
            step: Mutex::new(None),
        })
    }
    pub(crate) fn advance_after_reads(&self, reads: usize, seconds: u64, monotonic: u64) {
        *self.step.lock().unwrap() = Some((reads, seconds, monotonic));
    }
}
impl Clock for StepClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut step = self.step.lock().map_err(|_| ClockError::Unavailable)?;
        if let Some((remaining, seconds, monotonic)) = *step {
            if remaining == 0 {
                self.source.set(seconds, monotonic);
                *step = None;
            } else {
                *step = Some((remaining - 1, seconds, monotonic));
            }
        }
        self.source.read()
    }
}

#[test]
fn stable_follow_up_sample_rebaselines_after_suspend_gap() {
    let source = ManualClock::new(10_000);
    let clock = StableReplayClock::new(source.clone(), 300).unwrap();
    source.set(13_600, 1);
    assert!(matches!(
        clock.validate_observed(13_600, 10_000),
        Err(ReplayClockValidationError::Anomaly {
            direction: ReplayClockDirection::ForwardJump,
            ..
        })
    ));
    source.set(13_602, 3);
    assert!(clock.validate_observed(13_602, 10_000).is_ok());
    assert_eq!(clock.expected_wall_now().unwrap(), 13_602);
}

#[test]
fn inconsistent_follow_up_sample_remains_denied() {
    let source = ManualClock::new(10_000);
    let clock = StableReplayClock::new(source.clone(), 300).unwrap();
    for (wall, mono) in [(13_600, 1), (17_200, 3)] {
        source.set(wall, mono);
        assert!(matches!(
            clock.validate_observed(wall as i64, 10_000),
            Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::ForwardJump,
                ..
            })
        ));
    }
}

#[test]
fn clock_faults_and_regression_are_exact_and_do_not_rebaseline() {
    let source = ManualClock::new(10_000);
    let clock = StableReplayClock::new(source.clone(), 300).unwrap();
    source.fail(ClockError::Unavailable);
    assert!(matches!(
        clock.validate_observed(10_000, 10_000),
        Err(ReplayClockValidationError::Clock(ClockError::Unavailable))
    ));
    source.set(9_999, 1);
    assert_eq!(clock.now_secs(), Err(ClockError::WallClockRegression));
    source.set(10_001, 2);
    assert_eq!(clock.now_secs(), Ok(10_001));
    source.set(10_001, 1);
    assert_eq!(clock.now_secs(), Err(ClockError::MonotonicRegression));
    source.set(10_002, 3);
    assert_eq!(clock.expected_wall_now().unwrap(), 10_003);
}

#[test]
fn skew_boundary_and_durable_high_water_are_enforced() {
    let source = ManualClock::new(10_000);
    let clock = StableReplayClock::new(source, 300).unwrap();
    assert!(clock.validate_observed(10_300, 10_000).is_ok());
    assert!(matches!(
        clock.validate_observed(10_301, 10_000),
        Err(ReplayClockValidationError::Anomaly {
            direction: ReplayClockDirection::ForwardJump,
            ..
        })
    ));
    assert!(matches!(
        clock.validate_observed(10_000, 10_301),
        Err(ReplayClockValidationError::Anomaly {
            direction: ReplayClockDirection::Rollback,
            ..
        })
    ));
    assert!(matches!(
        clock.validate_observed(-1, 0),
        Err(ReplayClockValidationError::Clock(ClockError::BeforeEpoch))
    ));
}
