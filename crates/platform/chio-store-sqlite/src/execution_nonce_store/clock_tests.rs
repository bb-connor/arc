#![allow(clippy::unwrap_used)]
use super::*;
use crate::replay_clock::tests::ManualClock;
use chio_security_types::clock::ClockReading;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn expiry_between_initial_sample_and_writer_lock_keeps_database_unchanged() {
    let clock = crate::replay_clock::tests::StepClock::new(10_000);
    let store = SqliteExecutionNonceStore::open_in_memory_with_clock(4, clock.clone()).unwrap();
    let before = snapshot(&store);
    clock.advance_after_reads(1, 10_030, 30);
    assert!(matches!(
        store.reserve_for_dispatch("expired", 10_030, "owner"),
        Err(KernelError::Clock(ClockError::Expired))
    ));
    assert_eq!(snapshot(&store), before);
    assert!(store
        .reserve_for_dispatch("fresh", 10_031, "owner")
        .unwrap());
}

fn snapshot(store: &SqliteExecutionNonceStore) -> (i64, i64, i64) {
    store.pool.get().unwrap().query_row(
        "SELECT wall_clock_high_water, pruned_through, (SELECT COUNT(*) FROM chio_execution_nonces) FROM chio_execution_nonce_clock", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap()
}

#[test]
fn injected_clock_errors_and_overflow_leave_sql_unchanged() {
    let clock = ManualClock::new(10_000);
    let store = SqliteExecutionNonceStore::open_in_memory_with_clock(1, clock.clone()).unwrap();
    assert!(store.reserve_for_dispatch("a", 10_030, "owner-a").unwrap());
    let before = snapshot(&store);
    clock.fail(ClockError::Unavailable);
    assert!(matches!(
        store.reserve_until("a", 10_100),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(matches!(
        store.is_consumed("a"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(snapshot(&store), before);
    clock.set(9_999, 1);
    assert!(matches!(
        store.reserve_until("b", 10_030),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    clock.set(10_001, 2);
    assert!(matches!(
        store.reserve_until("b", i64::MAX),
        Err(KernelError::Clock(ClockError::Overflow))
    ));
    assert!(matches!(
        store.reserve_until("b", 10_030),
        Err(KernelError::ExecutionNonceCapacity)
    ));
    assert_eq!(snapshot(&store), before);
    assert!(!store.rollback_dispatch_reservation("a", "owner-b").unwrap());
    assert!(store.is_consumed("a").unwrap());
    clock.fail(ClockError::Unavailable);
    assert!(store.rollback_dispatch_reservation("a", "owner-a").unwrap());
}

#[test]
fn restart_preserves_exact_retention_and_rejects_clock_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonces.sqlite");
    let clock = ManualClock::new(10_000);
    let store = SqliteExecutionNonceStore::open_with_clock(&path, 4, clock.clone()).unwrap();
    assert!(store.reserve_until("a", 10_030).unwrap());
    assert!(!store.reserve_until("a", 10_200).unwrap());
    let retained: i64 = store
        .pool
        .get()
        .unwrap()
        .query_row(
            "SELECT expires_at FROM chio_execution_nonces WHERE nonce_id = 'a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, 10_090);
    drop(store);
    let store = SqliteExecutionNonceStore::open_with_clock(&path, 4, clock).unwrap();
    assert!(!store.reserve_until("a", 10_200).unwrap());
    drop(store);
    assert!(matches!(
        SqliteExecutionNonceStore::open_with_clock(&path, 4, ManualClock::new(9_000)),
        Err(SqliteExecutionNonceStoreError::ClockAnomaly {
            direction: ReplayClockDirection::Rollback,
            ..
        })
    ));
}

struct FailOnRead {
    source: Arc<ManualClock>,
    count: AtomicUsize,
    fail_at: AtomicUsize,
}
impl Clock for FailOnRead {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.count.fetch_add(1, Ordering::SeqCst) == self.fail_at.load(Ordering::SeqCst) {
            Err(ClockError::Unavailable)
        } else {
            self.source.read()
        }
    }
}

#[test]
fn clock_failure_inside_serialized_reservation_rolls_back() {
    let clock = Arc::new(FailOnRead {
        source: ManualClock::new(10_000),
        count: AtomicUsize::new(0),
        fail_at: AtomicUsize::new(usize::MAX),
    });
    let store = SqliteExecutionNonceStore::open_in_memory_with_clock(4, clock.clone()).unwrap();
    let before = snapshot(&store);
    clock.source.set(10_001, 1);
    clock
        .fail_at
        .store(clock.count.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
    assert!(matches!(
        store.reserve_for_dispatch("a", 10_030, "owner-a"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(snapshot(&store), before);
    assert!(store.reserve_for_dispatch("a", 10_030, "owner-a").unwrap());
}

#[test]
fn unavailable_clock_refuses_open_and_preserves_error_source() {
    let clock = ManualClock::new(10_000);
    clock.fail(ClockError::Unavailable);
    let Err(error) = SqliteExecutionNonceStore::open_in_memory_with_clock(4, clock) else {
        panic!("unavailable clock accepted")
    };
    assert!(std::error::Error::source(&error).is_some());
    assert!(matches!(
        error,
        SqliteExecutionNonceStoreError::Clock(ClockError::Unavailable)
    ));
}
