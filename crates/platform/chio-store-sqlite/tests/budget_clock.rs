use chio_kernel::{BudgetStore, BudgetStoreError, InMemoryBudgetStore};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_store_sqlite::SqliteBudgetStore;
use chio_test_support::prelude::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

struct TestClock {
    wall: AtomicU64,
    monotonic: AtomicU64,
    reads: AtomicUsize,
    fail_at: AtomicUsize,
}
impl TestClock {
    fn new() -> Self {
        Self {
            wall: AtomicU64::new(10_000),
            monotonic: AtomicU64::new(100),
            reads: AtomicUsize::new(0),
            fail_at: AtomicUsize::new(usize::MAX),
        }
    }
    fn fail_after(&self, successful_reads: usize) {
        self.fail_at.store(
            self.reads.load(Ordering::SeqCst) + successful_reads,
            Ordering::SeqCst,
        );
    }
    fn recover(&self) {
        self.fail_at.store(usize::MAX, Ordering::SeqCst);
        self.wall.store(10_000, Ordering::SeqCst);
        self.monotonic.store(100, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.reads.fetch_add(1, Ordering::SeqCst) >= self.fail_at.load(Ordering::SeqCst) {
            return Err(ClockError::Unavailable);
        }
        Ok(ClockReading::new(
            UnixMillis::new(self.wall.load(Ordering::SeqCst)),
            MonotonicInstant::from_nanos(self.monotonic.load(Ordering::SeqCst)),
        ))
    }
}

fn assert_refusal_preserves_usage(store: &dyn BudgetStore, clock: &TestClock) {
    assert!(store
        .try_increment("clocked", 0, Some(10))
        .test_expect("initial increment"));
    let before = store
        .get_usage("clocked", 0)
        .test_expect("usage")
        .test_expect("present");
    assert_eq!(before.updated_at, 10);
    for error in [
        ClockError::Unavailable,
        ClockError::WallClockRegression,
        ClockError::MonotonicRegression,
    ] {
        match error {
            ClockError::Unavailable => clock.fail_after(0),
            ClockError::WallClockRegression => clock.wall.store(9_999, Ordering::SeqCst),
            ClockError::MonotonicRegression => clock.monotonic.store(99, Ordering::SeqCst),
            _ => unreachable!(),
        }
        assert!(
            matches!(store.try_increment("clocked", 0, Some(10)), Err(BudgetStoreError::Clock(actual)) if actual == error)
        );
        clock.recover();
        assert_eq!(
            store.get_usage("clocked", 0).test_expect("unchanged"),
            Some(before.clone())
        );
    }
    assert!(store
        .try_increment("clocked", 0, Some(10))
        .test_expect("retry"));
    assert_eq!(
        store
            .get_usage("clocked", 0)
            .test_expect("usage")
            .test_expect("present")
            .invocation_count,
        2
    );
}

#[test]
fn in_memory_clock_failure_and_regression_precede_mutation() {
    let clock = Arc::new(TestClock::new());
    let store = InMemoryBudgetStore::with_clock(clock.clone());
    assert_refusal_preserves_usage(&store, &clock);
}

#[test]
fn sqlite_clock_failure_and_regression_leave_durable_state_unchanged() {
    let directory = tempfile::tempdir().test_expect("directory");
    let path = directory.path().join("clock.sqlite");
    let clock = Arc::new(TestClock::new());
    let store = SqliteBudgetStore::open_with_clock(&path, clock.clone()).test_expect("store");
    assert_refusal_preserves_usage(&store, &clock);
    drop(store);
    let reopened = SqliteBudgetStore::open_with_clock(&path, clock).test_expect("reopen");
    assert_eq!(
        reopened
            .get_usage("clocked", 0)
            .test_expect("usage")
            .test_expect("present")
            .invocation_count,
        2
    );
}

#[test]
fn sqlite_clock_failure_after_sequence_allocation_rolls_back_every_table() {
    let directory = tempfile::tempdir().test_expect("directory");
    let path = directory.path().join("rollback.sqlite");
    let clock = Arc::new(TestClock::new());
    let store = SqliteBudgetStore::open_with_clock(&path, clock.clone()).test_expect("store");
    assert!(store
        .try_increment("clocked", 0, Some(10))
        .test_expect("initial"));
    let before = store.get_usage("clocked", 0).test_expect("usage");
    let before_events = store
        .list_mutation_events(100, None, None)
        .test_expect("events");
    // Read at begin_write and before the usage write; refuse at event publication.
    clock.fail_after(2);
    assert!(matches!(
        store.try_increment("clocked", 0, Some(10)),
        Err(BudgetStoreError::Clock(ClockError::Unavailable))
    ));
    clock.recover();
    assert_eq!(store.get_usage("clocked", 0).test_expect("usage"), before);
    assert_eq!(
        store
            .list_mutation_events(100, None, None)
            .test_expect("events"),
        before_events
    );
    drop(store);
    let reopened = SqliteBudgetStore::open_with_clock(&path, clock).test_expect("reopen");
    assert!(reopened
        .try_increment("clocked", 0, Some(10))
        .test_expect("retry"));
    assert_eq!(
        reopened
            .get_usage("clocked", 0)
            .test_expect("usage")
            .test_expect("present")
            .seq,
        2
    );
}

#[test]
fn sqlite_clock_failure_denies_cached_mutation_replay() {
    let directory = tempfile::tempdir().test_expect("directory");
    let clock = Arc::new(TestClock::new());
    let store =
        SqliteBudgetStore::open_with_clock(directory.path().join("retry.sqlite"), clock.clone())
            .test_expect("store");
    assert!(store
        .try_increment_with_event_id("clocked", 0, Some(10), Some("event"))
        .test_expect("initial"));
    clock.fail_after(0);
    assert!(matches!(
        store.try_increment_with_event_id("clocked", 0, Some(10), Some("event")),
        Err(BudgetStoreError::Clock(ClockError::Unavailable))
    ));
    clock.recover();
    assert!(store
        .try_increment_with_event_id("clocked", 0, Some(10), Some("event"))
        .test_expect("retry"));
    assert_eq!(
        store
            .get_usage("clocked", 0)
            .test_expect("usage")
            .test_expect("present")
            .invocation_count,
        1
    );
}
