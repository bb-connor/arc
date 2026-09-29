use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::{Arc, Mutex};

const EPOCH: u64 = 1_800_000_000_000;

struct TestClock(Mutex<Result<ClockReading, ClockError>>);

impl TestClock {
    fn reading(unix_ms: u64, monotonic: u64) -> ClockReading {
        ClockReading::new(
            UnixMillis::new(unix_ms),
            MonotonicInstant::from_nanos(monotonic),
        )
    }

    fn set(&self, reading: Result<ClockReading, ClockError>) -> AnchoredTestResult {
        *self.0.lock().map_err(|_| "test clock poisoned")? = reading;
        Ok(())
    }
}

impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}

fn injected_fixture() -> AnchoredTestResult<(Fixture, Arc<TestClock>)> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_lock_root(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let clock = Arc::new(TestClock(Mutex::new(Ok(TestClock::reading(EPOCH, 100)))));
    let authority =
        SqliteAuthorityStore::open_serving_with_clock(&database, &lock_root, clock.clone())?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    Ok((
        Fixture {
            _temp: temp,
            database,
            lock_root,
            authority,
            store,
            fence,
        },
        clock,
    ))
}

#[test]
fn admission_uses_injected_authority_time_across_restart() -> AnchoredTestResult {
    let (fixture, clock) = injected_fixture()?;
    assert_eq!(fixture.store.observed_authority_time()?.get(), EPOCH);
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "injected-before",
        "clock-cap",
    );
    fixture.store.begin(&operation, &fixture.fence, EPOCH)?;
    assert_eq!(
        load_admission_commit_head(&*fixture.store.connection()?)?.trusted_time_high_water_unix_ms,
        EPOCH
    );
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    clock.set(Ok(TestClock::reading(EPOCH + 1_000, 200)))?;
    let reopened = SqliteAuthorityStore::open_serving_with_clock(&database, &lock_root, clock)?;
    let store = reopened.admission_operation_store();
    assert_eq!(
        store.load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    let next = prepared_operation(
        &reopened.mutation_fence(),
        AdmissionOperationKind::ToolDispatch,
        "injected-after",
        "clock-cap",
    );
    store.begin(&next, &reopened.mutation_fence(), EPOCH + 1_000)?;
    assert_eq!(
        load_admission_commit_head(&*store.connection()?)?.trusted_time_high_water_unix_ms,
        EPOCH + 1_000
    );
    Ok(())
}

#[test]
fn injected_authority_preserves_caller_skew_limit() -> AnchoredTestResult {
    let (fixture, _) = injected_fixture()?;
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "injected-skew",
        "clock-cap",
    );
    let head = load_admission_commit_head(&*fixture.store.connection()?)?;
    for caller_time in [EPOCH - 300_001, EPOCH + 300_001] {
        assert!(
            matches!(fixture.store.begin(&operation, &fixture.fence, caller_time), Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("permitted system-clock skew"))
        );
        assert_eq!(
            load_admission_commit_head(&*fixture.store.connection()?)?,
            head
        );
    }
    fixture
        .store
        .begin(&operation, &fixture.fence, EPOCH + 300_000)?;
    Ok(())
}

#[test]
fn injected_clock_faults_deny_even_exact_admission_replay() -> AnchoredTestResult {
    for (reading, expected) in [
        (Err(ClockError::Unavailable), ClockError::Unavailable),
        (
            Ok(TestClock::reading(EPOCH - 1, 100)),
            ClockError::WallClockRegression,
        ),
        (
            Ok(TestClock::reading(EPOCH, 99)),
            ClockError::MonotonicRegression,
        ),
    ] {
        let (fixture, clock) = injected_fixture()?;
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "injected-replay",
            "clock-cap",
        );
        fixture.store.begin(&operation, &fixture.fence, EPOCH)?;
        let head = load_admission_commit_head(&*fixture.store.connection()?)?;
        clock.set(reading)?;
        assert!(
            matches!(fixture.store.begin(&operation, &fixture.fence, EPOCH), Err(AdmissionOperationStoreError::Invariant(message)) if message == expected.code())
        );
        assert_eq!(
            load_admission_commit_head(&*fixture.store.connection()?)?,
            head
        );
    }
    Ok(())
}

#[test]
fn stale_caller_time_cannot_extend_injected_authority_lease() -> AnchoredTestResult {
    let (fixture, clock) = injected_fixture()?;
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "injected-lease",
        "clock-cap",
    );
    fixture.store.begin(&operation, &fixture.fence, EPOCH)?;
    let claim = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        1,
        &identifier("claimant_id", "injected-worker"),
        EPOCH,
        EPOCH + 1_000,
        &fixture.fence,
    )?;
    clock.set(Ok(TestClock::reading(EPOCH + 1_000, 1_000_000_100)))?;
    assert!(matches!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            claim.untrusted_claim(),
            EPOCH,
            &fixture.fence
        ),
        Err(AdmissionOperationStoreError::Operation(
            AdmissionOperationError::LeaseExpired
        ))
    ));
    Ok(())
}
