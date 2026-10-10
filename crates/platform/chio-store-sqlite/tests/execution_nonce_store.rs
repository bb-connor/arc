//! Public nonce custody contract with an injected clock and exact signed expiry.
use chio_kernel::{ExecutionNonceStore, KernelError};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_store_sqlite::SqliteExecutionNonceStore;
use chio_test_support::prelude::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

struct TestClock(AtomicU64);
impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(10_000)))
    }
    fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let seconds = self.0.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::from_secs(seconds)?,
            MonotonicInstant::from_nanos(
                seconds
                    .checked_mul(1_000_000_000)
                    .ok_or(ClockError::Overflow)?,
            ),
        ))
    }
}
fn store(capacity: usize, clock: Arc<TestClock>) -> SqliteExecutionNonceStore {
    SqliteExecutionNonceStore::open_in_memory_with_clock(capacity, clock).test_expect("store")
}

#[test]
fn fresh_nonce_is_reserved() {
    let store = store(4, TestClock::new());
    assert!(store
        .reserve_until("nonce-a", 10_030)
        .test_expect("reserve"));
}

#[test]
fn replayed_nonce_is_rejected_within_retention() {
    let store = store(4, TestClock::new());
    assert!(store
        .reserve_until("nonce-b", 10_030)
        .test_expect("reserve"));
    assert!(!store.reserve_until("nonce-b", 10_100).test_expect("replay"));
}

#[test]
fn expired_row_is_pruned_and_slot_becomes_free() {
    let clock = TestClock::new();
    let store = store(1, clock.clone());
    assert!(store
        .reserve_until("nonce-c", 10_010)
        .test_expect("reserve"));
    clock.set(10_069);
    assert!(matches!(
        store.reserve_until("next", 10_100),
        Err(KernelError::ExecutionNonceCapacity)
    ));
    clock.set(10_070);
    assert!(store
        .reserve_until("next", 10_100)
        .test_expect("reclaimed capacity"));
}

#[test]
fn persists_consumed_marker_across_reopen() {
    let directory = tempfile::tempdir().test_expect("directory");
    let path = directory.path().join("replay.sqlite");
    let clock = TestClock::new();
    {
        let store =
            SqliteExecutionNonceStore::open_with_clock(&path, 4, clock.clone()).test_expect("open");
        assert!(store
            .reserve_until("persistent-id", 10_120)
            .test_expect("reserve"));
        assert!(store.is_consumed("persistent-id").test_expect("read"));
    }
    let store = SqliteExecutionNonceStore::open_with_clock(&path, 4, clock).test_expect("reopen");
    assert!(store.is_consumed("persistent-id").test_expect("read"));
    assert!(!store
        .reserve_until("persistent-id", 10_120)
        .test_expect("replay"));
}

#[test]
fn expired_nonce_is_refused_without_creating_a_marker() {
    let store = store(1, TestClock::new());
    assert!(matches!(
        store.reserve_until("expired", 10_000),
        Err(KernelError::Clock(ClockError::Expired))
    ));
    assert!(!store.is_consumed("expired").test_expect("absent marker"));
    assert!(store
        .reserve_until("valid", 10_030)
        .test_expect("capacity remains"));
}

#[test]
fn distinct_ids_each_succeed() {
    let store = store(4, TestClock::new());
    for id in ["a", "b", "c"] {
        assert!(store.reserve_until(id, 10_030).test_expect("reserve"));
    }
    for id in ["a", "b", "c"] {
        assert!(!store.reserve_until(id, 10_030).test_expect("replay"));
    }
}

#[test]
fn owned_rollback_cannot_release_another_attempt() {
    let store = store(1, TestClock::new());
    assert!(store
        .reserve_for_dispatch("a", 10_030, "owner")
        .test_expect("reserve"));
    assert!(!store
        .rollback_dispatch_reservation("a", "other")
        .test_expect("wrong owner"));
    assert!(store
        .rollback_dispatch_reservation("a", "owner")
        .test_expect("rollback"));
    assert!(store
        .reserve_for_dispatch("a", 10_030, "next")
        .test_expect("retry"));
    assert!(!store
        .rollback_dispatch_reservation("a", "owner")
        .test_expect("old owner"));
}

#[test]
fn configured_capacity_preserves_live_markers() {
    let store = store(1, TestClock::new());
    assert!(store.reserve_until("a", 10_030).test_expect("reserve"));
    assert!(matches!(
        store.reserve_until("b", 10_030),
        Err(KernelError::ExecutionNonceCapacity)
    ));
    assert!(!store
        .reserve_until("a", 10_030)
        .test_expect("replay retained"));
}
