use super::{CircuitBreaker, CircuitBreakerConfig, CircuitState, TokenBucket, TtlCache};
use chio_security_types::clock::{
    Clock, ClockError, ClockFence, ClockReading, MonotonicInstant, UnixMillis,
};
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
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

/// Wall source with the production fencing behavior: a sample below the
/// high-water mark fails with `WallClockRegression`.
struct FencedWallClock(Mutex<(u64, ClockFence)>);
impl FencedWallClock {
    fn new(unix_ms: u64) -> Self {
        Self(Mutex::new((unix_ms, ClockFence::default())))
    }
    fn set(&self, unix_ms: u64) {
        self.0.lock().unwrap_or_else(|e| panic!("wall lock: {e}")).0 = unix_ms;
    }
}
impl Clock for FencedWallClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut state = self.0.lock().map_err(|_| ClockError::Unavailable)?;
        let unix_ms = state.0;
        state.1.observe(ClockReading::new(
            UnixMillis::new(unix_ms),
            MonotonicInstant::from_nanos(0),
        ))
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_fenced_wall_regression_does_not_fail_resilience_clock_reads() {
    let wall = Arc::new(FencedWallClock::new(10_000));
    let clock: Arc<dyn Clock> = Arc::new(super::TokioClock::with_wall_clock(wall.clone()));
    let breaker = CircuitBreaker::with_clock(CircuitBreakerConfig::default(), clock.clone());
    let cache = TtlCache::with_clock(NonZeroUsize::MIN, clock.clone());
    let bucket = TokenBucket::with_clock(10.0, 10, clock.clone());
    cache.insert("key", "allow", Duration::from_secs(60));
    assert!(breaker.allow_call());
    assert!(clock.unix_millis().is_ok());

    wall.set(5_000);
    tokio::time::advance(Duration::from_millis(1)).await;

    assert_eq!(clock.unix_millis(), Err(ClockError::WallClockRegression));
    assert!(clock.monotonic().is_ok());
    assert!(breaker.allow_call());
    assert_eq!(breaker.current_state(), CircuitState::Closed);
    assert_eq!(cache.get(&"key"), Some("allow"));
    assert!(bucket.try_acquire());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_wall_regression_still_fails_the_wall_read_closed() {
    let wall = Arc::new(FencedWallClock::new(10_000));
    let clock = super::TokioClock::with_wall_clock(wall.clone());
    assert!(clock.unix_millis().is_ok());
    wall.set(5_000);
    assert_eq!(clock.unix_millis(), Err(ClockError::WallClockRegression));
    assert!(clock.monotonic().is_ok());
}

struct CountingGuard(AtomicU32);
#[async_trait::async_trait]
impl super::ExternalGuard for CountingGuard {
    fn name(&self) -> &str {
        "counting"
    }
    fn cache_key(&self, _ctx: &super::GuardCallContext) -> Option<String> {
        None
    }
    async fn eval(
        &self,
        _ctx: &super::GuardCallContext,
    ) -> Result<chio_kernel::Verdict, super::ExternalGuardError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(chio_kernel::Verdict::Deny)
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_wall_regression_never_skips_the_guard_even_when_open_circuits_allow() {
    let wall = Arc::new(FencedWallClock::new(10_000));
    let clock: Arc<dyn Clock> = Arc::new(super::TokioClock::with_wall_clock(wall.clone()));
    let guard = Arc::new(CountingGuard(AtomicU32::new(0)));
    let adapter = super::AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit_open_verdict(super::CircuitOpenVerdict::Allow)
        .clock(clock.clone())
        .build();
    let ctx = super::GuardCallContext::default();
    assert!(clock.unix_millis().is_ok());
    assert_eq!(adapter.evaluate(&ctx).await, chio_kernel::Verdict::Deny);

    wall.set(5_000);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(clock.unix_millis(), Err(ClockError::WallClockRegression));

    assert_eq!(adapter.evaluate(&ctx).await, chio_kernel::Verdict::Deny);
    assert_eq!(guard.0.load(Ordering::SeqCst), 2);
    assert_eq!(adapter.circuit_state(), CircuitState::Closed);
}
