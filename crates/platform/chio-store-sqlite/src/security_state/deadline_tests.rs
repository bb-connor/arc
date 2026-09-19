//! Real SQLite lock contention must not turn an expired deadline into authority.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId};

use super::*;

#[cfg(unix)]
mod declassification;
mod lineage;
mod overlays;
mod replay;
mod scheduler;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type BusyRelease = Box<dyn FnOnce() -> bool>;

thread_local! {
    static BUSY_RELEASE: RefCell<Option<BusyRelease>> = const { RefCell::new(None) };
}

fn release_when_busy(_: i32) -> bool {
    let release = BUSY_RELEASE.with(|slot| slot.borrow_mut().take());
    release.is_some_and(|release| release())
}

struct ResetBusyRelease;

impl Drop for ResetBusyRelease {
    fn drop(&mut self) {
        BUSY_RELEASE.with(|slot| slot.borrow_mut().take());
    }
}

struct Clock(AtomicU64);

impl SecurityStateClock for Clock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        let now = self.0.load(Ordering::Acquire);
        if now == u64::MAX {
            return Err(PortError::unavailable());
        }
        Ok(now)
    }
}

struct Fixture {
    store: SqliteSecurityStateStore,
    clock: Arc<Clock>,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let clock = Arc::new(Clock(AtomicU64::new(1_000)));
        let store = SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("security.db"),
            clock.clone(),
        )?;
        Ok(Self {
            store,
            clock,
            directory,
        })
    }

    /// The busy handler advances time only after SQLite encounters a real lock,
    /// then releases the other connection. No sleeps, timing races, or production
    /// hooks are needed. Reads use rollback journaling to exercise a read lock;
    /// mutations retain the production WAL profile and wait on BEGIN IMMEDIATE.
    fn after_database_wait<T>(
        &self,
        read: bool,
        now: u64,
        operation: impl FnOnce(&SqliteSecurityStateStore) -> PortResult<T>,
    ) -> TestResult<PortResult<T>> {
        {
            let connection = self.store.connection()?;
            if read {
                connection.pragma_update(None, "journal_mode", "DELETE")?;
            }
            connection.busy_handler(Some(release_when_busy))?;
        }
        let blocker = Connection::open(self.directory.path().join("security.db"))?;
        blocker.execute_batch(if read {
            "BEGIN EXCLUSIVE"
        } else {
            "BEGIN IMMEDIATE"
        })?;
        let clock = self.clock.clone();
        let released = Arc::new(AtomicBool::new(false));
        let released_in_callback = released.clone();
        let _reset = ResetBusyRelease;
        BUSY_RELEASE.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(move || {
                clock.0.store(now, Ordering::Release);
                let committed = blocker.execute_batch("COMMIT").is_ok();
                released_in_callback.store(committed, Ordering::Release);
                committed
            }));
        });
        let result = operation(&self.store);
        assert!(
            released.load(Ordering::Acquire),
            "operation did not resume after a real database lock"
        );
        self.store
            .connection()?
            .busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(result)
    }

    fn flow_request(&self) -> TestResult<EgressFenceRequest> {
        let key = FlowStateKey {
            tenant_id: TenantId::new("tenant")?,
            principal_id: chio_security_types::PrincipalId::new("principal")?,
            lineage_id: LineageId::new("lineage")?,
            session_id: SessionId::new("session")?,
            isolation_epoch_id: IsolationEpochId::new("epoch")?,
        };
        let snapshot = self.store.join(&FlowJoinRequest {
            key: key.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: RecordId::new("initial-join")?,
        })?;
        Ok(EgressFenceRequest {
            key,
            request_id: chio_security_types::ports::RequestId::new("request")?,
            request_hash: Digest32::new([1; 32]),
            expected_context_generation: snapshot.context_generation,
            expires_at_unix_ms: 1_500,
        })
    }

    fn lineage_request(&self) -> TestResult<LineageFenceRequest> {
        Ok(LineageFenceRequest {
            tenant_id: TenantId::new("tenant")?,
            action_id: ActionId::new("action")?,
            expected_commit_index: 1,
            expected_affected_set_hash: Digest32::new([2; 32]),
            scheduler_lease_owner_id: LeaseOwnerId::new("worker")?,
            scheduler_fencing_token: 1,
            expires_at_unix_ms: 1_500,
        })
    }

    fn scheduler_request(&self) -> TestResult<SchedulerClaimRequest> {
        let body = b"{}";
        let mut hash = [0; 32];
        hash.copy_from_slice(sha256(body).as_ref());
        self.store.create(&ResponsePlanRecord {
            tenant_id: TenantId::new("tenant")?,
            action_id: ActionId::new("action")?,
            generation: 0,
            state: RecordId::new("active")?,
            canonical_body: CanonicalBody::new(body.to_vec())?,
            body_hash: Digest32::new(hash),
            due_at_unix_ms: Some(999),
        })?;
        Ok(SchedulerClaimRequest {
            tenant_id: TenantId::new("tenant")?,
            claim_id: RecordId::new("claim")?,
            lease_owner_id: LeaseOwnerId::new("worker")?,
            now_unix_ms: 1_000,
            lease_expires_at_unix_ms: 1_500,
            max_claims: 1,
        })
    }
}

fn assert_kind<T>(result: PortResult<T>, expected: chio_security_types::ports::PortErrorKind) {
    match result {
        Err(error) => assert_eq!(error.kind(), expected),
        Ok(_) => panic!("expired operation unexpectedly succeeded"),
    }
}

#[test]
fn egress_acquisition_rechecks_expiry_after_sqlite_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.flow_request()?;
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.acquire_egress_fence(&request))?,
        chio_security_types::ports::PortErrorKind::Conflict,
    );
    let count: i64 = fixture.store.connection()?.query_row(
        "SELECT count(*) FROM security_egress_fences",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn egress_retry_rechecks_expiry_after_sqlite_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.flow_request()?;
    fixture.store.acquire_egress_fence(&request)?;
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.acquire_egress_fence(&request))?,
        chio_security_types::ports::PortErrorKind::Conflict,
    );
    Ok(())
}

#[test]
fn egress_validation_rechecks_expiry_after_sqlite_read_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.flow_request()?;
    let fence = fixture.store.acquire_egress_fence(&request)?;
    fixture.store.validate_egress_fence(&fence)?;
    assert_kind(
        fixture.after_database_wait(true, 1_500, |store| store.validate_egress_fence(&fence))?,
        chio_security_types::ports::PortErrorKind::Conflict,
    );
    Ok(())
}

#[test]
fn live_egress_after_write_wait_still_works() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.flow_request()?;
    let fence = fixture
        .after_database_wait(false, 1_499, |store| store.acquire_egress_fence(&request))??;
    fixture.store.validate_egress_fence(&fence)?;
    Ok(())
}

#[test]
fn lineage_acquisition_rechecks_expiry_after_sqlite_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.lineage_request()?;
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| {
            LineageFenceStore::acquire(store, &request)
        })?,
        chio_security_types::ports::PortErrorKind::InvalidData,
    );
    Ok(())
}

#[test]
fn lineage_query_rechecks_expiry_after_sqlite_read_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let fence = LineageFenceStore::acquire(&fixture.store, &fixture.lineage_request()?)?;
    let action = TenantScopedId {
        tenant_id: fence.tenant_id.clone(),
        id: RecordId::new(fence.action_id.as_str())?,
    };
    assert!(LineageFenceStore::query(&fixture.store, &action)?.is_some());
    assert!(fixture
        .after_database_wait(true, 1_500, |store| LineageFenceStore::query(
            store, &action
        ))??
        .is_none());
    Ok(())
}

#[test]
fn scheduler_claim_rechecks_expiry_after_sqlite_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.scheduler_request()?;
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.claim_due(&request))?,
        chio_security_types::ports::PortErrorKind::InvalidData,
    );
    let count: i64 = fixture.store.connection()?.query_row(
        "SELECT count(*) FROM security_scheduler_leases",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn scheduler_validation_rechecks_expiry_after_sqlite_read_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.scheduler_request()?;
    let work = fixture.store.claim_due(&request)?.remove(0);
    fixture.store.validate_lease(&work)?;
    assert_kind(
        fixture.after_database_wait(true, 1_500, |store| store.validate_lease(&work))?,
        chio_security_types::ports::PortErrorKind::Conflict,
    );
    Ok(())
}

#[test]
fn deferred_transaction_pins_snapshot_before_reading_clock() -> TestResult {
    let fixture = Fixture::new()?;
    let mut connection = fixture.store.connection()?;
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    connection.busy_handler(Some(release_when_busy))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // BEGIN DEFERRED has not performed a read. The other connection can still
    // obtain an exclusive lock, so the clock helper itself must wait on a read.
    let blocker = Connection::open(fixture.directory.path().join("security.db"))?;
    blocker.execute_batch("BEGIN EXCLUSIVE")?;
    let clock = fixture.clock.clone();
    let _reset = ResetBusyRelease;
    BUSY_RELEASE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            clock.0.store(1_500, Ordering::Release);
            blocker.execute_batch("COMMIT").is_ok()
        }));
    });
    assert_eq!(
        fixture.store.trusted_now_in_transaction(&transaction)?,
        1_500
    );
    assert!(BUSY_RELEASE.with(|slot| slot.borrow().is_none()));
    transaction.commit()?;
    Ok(())
}
