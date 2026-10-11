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

#[cfg(unix)]
#[test]
fn serving_owner_injects_one_clock_and_fence_into_every_budget_handle() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let directory = tempfile::tempdir().test_expect("directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .test_expect("private authority directory");
    let path = directory.path().join("authority.sqlite");
    let locks = directory.path().join("locks");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&locks)
        .test_expect("lock directory");
    chio_store_sqlite::SqliteAuthorityStore::provision(&path, &locks).test_expect("provision");
    let clock = Arc::new(TestClock::new());
    let owner = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
        &path,
        &locks,
        clock.clone(),
    )
    .test_expect("serving owner");
    use chio_kernel::budget_store::{
        BudgetAdmissionBinding, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
        BudgetEventAuthority, BudgetInvocationQuota, BudgetQuotaKey,
    };
    use chio_kernel::CanonicalRevocationSet;
    let fence = owner.mutation_fence();
    let request = BudgetAuthorizeHoldRequest {
        capability_id: "clocked".into(),
        grant_index: 0,
        max_invocations: Some(10),
        invocation_quotas: vec![BudgetInvocationQuota {
            key: BudgetQuotaKey::grant("clocked", 0),
            max_invocations: 10,
        }],
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: "clocked-operation".into(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec!["clocked".into()])
                .test_expect("revocation set"),
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(100),
        hold_id: Some("clocked-hold".into()),
        event_id: Some("clocked-event".into()),
        authority: Some(BudgetEventAuthority {
            authority_id: fence.store_uuid,
            lease_id: fence.lease_id,
            lease_epoch: fence.owner_epoch,
        }),
    };
    let first = owner.budget_store();
    let second = owner.budget_store();
    clock.wall.store(9_999, Ordering::SeqCst);
    let refused = first.authorize_budget_hold(request.clone());
    assert!(
        matches!(
            &refused,
            Err(BudgetStoreError::Clock(ClockError::WallClockRegression))
        ),
        "{refused:?}"
    );
    clock.recover();
    assert!(first.get_usage("clocked", 0).test_expect("usage").is_none());
    assert!(matches!(
        first
            .authorize_budget_hold(request.clone())
            .test_expect("authorize"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let before = first.get_usage("clocked", 0).test_expect("usage");
    assert_eq!(before.as_ref().test_expect("usage present").updated_at, 10);
    clock.wall.store(9_999, Ordering::SeqCst);
    let refused = second.authorize_budget_hold(request.clone());
    assert!(
        matches!(
            &refused,
            Err(BudgetStoreError::Clock(ClockError::WallClockRegression))
        ),
        "{refused:?}"
    );
    clock.recover();
    assert_eq!(second.get_usage("clocked", 0).test_expect("usage"), before);
    clock.fail_after(0);
    let refused = owner.budget_store().authorize_budget_hold(request);
    assert!(
        matches!(
            &refused,
            Err(BudgetStoreError::Clock(ClockError::Unavailable))
        ),
        "{refused:?}"
    );
}
