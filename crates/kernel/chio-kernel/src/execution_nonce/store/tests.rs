#![allow(
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
use super::*;
use chio_security_types::clock::{ClockReading, MonotonicInstant};

struct ManualClock(Mutex<Result<ClockReading, ClockError>>);
impl ManualClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Ok(reading(1_000, 0)))))
    }
    fn set(&self, value: Result<ClockReading, ClockError>) {
        *self.0.lock().unwrap() = value;
    }
}
impl Clock for ManualClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}
fn reading(wall: u64, monotonic: u64) -> ClockReading {
    ClockReading::new(
        UnixMillis::from_secs(wall).unwrap(),
        MonotonicInstant::from_nanos(monotonic),
    )
}

#[test]
fn exact_signed_expiry_owner_rollback_and_capacity() {
    let clock = ManualClock::new();
    let store = InMemoryExecutionNonceStore::with_clock(1, clock.clone());
    assert!(store.reserve_for_dispatch("a", 1_030, "owner-a").unwrap());
    assert!(!store.reserve_until("a", 1_060).unwrap());
    assert!(!store.rollback_dispatch_reservation("a", "owner-b").unwrap());
    assert!(matches!(
        store.reserve_until("b", 1_050),
        Err(KernelError::ExecutionNonceCapacity)
    ));
    assert!(store.is_consumed("a").unwrap());
    assert!(store.rollback_dispatch_reservation("a", "owner-a").unwrap());
    assert!(store.reserve_until("a", 1_030).unwrap());
    clock.set(Ok(reading(1_029, 50_000_000_000)));
    assert!(store.is_consumed("a").unwrap());
    clock.set(Ok(reading(1_030, 51_000_000_000)));
    assert!(!store.is_consumed("a").unwrap());
    assert!(matches!(
        store.reserve_until("a", 1_030),
        Err(KernelError::Clock(ClockError::Expired))
    ));
    assert!(store.reserve_until("b", 1_050).unwrap());
}

#[test]
fn clock_faults_and_overflow_refuse_without_losing_custody() {
    let clock = ManualClock::new();
    let store = InMemoryExecutionNonceStore::with_clock(2, clock.clone());
    assert!(store.reserve_for_dispatch("a", 1_030, "owner-a").unwrap());
    clock.set(Err(ClockError::Unavailable));
    assert!(matches!(
        store.reserve_until("b", 1_030),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(matches!(
        store.is_consumed("a"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(store.rollback_dispatch_reservation("a", "owner-a").unwrap());
    clock.set(Ok(reading(999, 1)));
    assert!(matches!(
        store.reserve_until("b", 1_030),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    clock.set(Ok(reading(1_000, 2)));
    assert!(matches!(
        store.reserve_until("overflow", i64::MAX),
        Err(KernelError::Clock(ClockError::Overflow))
    ));
    assert!(matches!(
        store.reserve_until("negative", -1),
        Err(KernelError::Clock(ClockError::BeforeEpoch))
    ));
    assert!(store.reserve_until("b", 1_030).unwrap());
}

#[test]
fn concurrent_reservations_consume_a_nonce_once() {
    let store = Arc::new(InMemoryExecutionNonceStore::with_clock(
        8,
        ManualClock::new(),
    ));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || store.reserve_until("same", 1_030).unwrap())
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|reserved| *reserved)
            .count(),
        1
    );
}

#[test]
fn zero_capacity_never_admits_a_nonce() {
    let store = InMemoryExecutionNonceStore::with_clock(0, ManualClock::new());
    assert!(matches!(
        store.reserve_until("a", 1_030),
        Err(KernelError::ExecutionNonceCapacity)
    ));
    assert!(!store.is_consumed("a").unwrap());
}
