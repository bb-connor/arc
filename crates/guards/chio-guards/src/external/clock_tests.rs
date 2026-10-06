use super::{CircuitBreaker, CircuitBreakerConfig, CircuitState, TokenBucket, TtlCache};
use chio_security_types::clock::{
    Clock, ClockError, ClockFence, ClockReading, MonotonicInstant, UnixMillis,
};
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

struct TestClock(Mutex<(Result<ClockReading, ClockError>, ClockFence)>);
impl TestClock {
    fn new(sample: Result<ClockReading, ClockError>) -> Self {
        Self(Mutex::new((sample, ClockFence::default())))
    }
    fn set(&self, sample: Result<ClockReading, ClockError>) {
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("clock lock: {e}"))
            .0 = sample;
    }
}
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut state = self.0.lock().map_err(|_| ClockError::Unavailable)?;
        let sample = state.0?;
        state.1.observe(sample)
    }
}
fn sample(unix_ms: u64, mono_ms: u64) -> Result<ClockReading, ClockError> {
    Ok(ClockReading::new(
        UnixMillis::new(unix_ms),
        MonotonicInstant::from_nanos(mono_ms * 1_000_000),
    ))
}

#[test]
fn clock_failure_and_regression_cannot_release_cache_or_breaker_calls() {
    let clock = Arc::new(TestClock::new(sample(1_000, 100)));
    let cache = TtlCache::with_clock(NonZeroUsize::MIN, clock.clone());
    cache.insert("key", "allow", Duration::from_millis(20));
    assert_eq!(cache.get(&"key"), Some("allow"));
    let breaker = CircuitBreaker::with_clock(CircuitBreakerConfig::default(), clock.clone());
    assert!(breaker.allow_call());
    for invalid in [
        Err(ClockError::Unavailable),
        sample(999, 101),
        sample(1001, 99),
    ] {
        clock.set(invalid);
        assert_eq!(cache.get(&"key"), None);
        assert!(!breaker.allow_call());
        assert_eq!(breaker.current_state(), CircuitState::Open);
    }
    // Stalled epoch time still cannot preserve an expired monotonic cache hit.
    clock.set(sample(1_000, 120));
    assert_eq!(cache.get(&"key"), None);
}

#[test]
fn failed_initial_clock_does_not_mint_a_recovery_burst() {
    let clock = Arc::new(TestClock::new(Err(ClockError::Unavailable)));
    let bucket = TokenBucket::with_clock(1.0, 10, clock.clone());
    assert!(!bucket.try_acquire());
    clock.set(sample(1000, 0));
    assert!(!bucket.try_acquire());
    assert_eq!(bucket.available(), 0.0);
    clock.set(sample(1000, 1000));
    assert!(bucket.try_acquire());
    assert!(!bucket.try_acquire());
    clock.set(sample(1000, 999));
    assert!(!bucket.try_acquire());
}

struct SettableWallClock(Mutex<u64>);
impl Clock for SettableWallClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let unix_ms = *self.0.lock().map_err(|_| ClockError::Unavailable)?;
        Ok(ClockReading::new(
            UnixMillis::new(unix_ms),
            MonotonicInstant::from_nanos(0),
        ))
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_backward_wall_clock_step_does_not_open_the_circuit_or_drop_cache_hits() {
    let wall = Arc::new(SettableWallClock(Mutex::new(10_000)));
    let clock: Arc<dyn Clock> = Arc::new(super::TokioClock::with_wall_clock(wall.clone()));
    let breaker = CircuitBreaker::with_clock(CircuitBreakerConfig::default(), clock.clone());
    let cache = TtlCache::with_clock(NonZeroUsize::MIN, clock.clone());
    let bucket = TokenBucket::with_clock(10.0, 10, clock);
    cache.insert("key", "allow", Duration::from_secs(60));
    assert!(breaker.allow_call());

    *wall.0.lock().unwrap_or_else(|e| panic!("wall lock: {e}")) = 5_000;
    tokio::time::advance(Duration::from_millis(1)).await;

    assert!(breaker.allow_call());
    assert_eq!(breaker.current_state(), CircuitState::Closed);
    assert_eq!(cache.get(&"key"), Some("allow"));
    assert!(bucket.try_acquire());
}
