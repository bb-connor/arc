//! Real executor claims, report replay and reopen against an independent epoch.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::{Arc, Mutex};

const EPOCH: u64 = 1_800_000_000_000;
struct TestClock(Mutex<Result<ClockReading, ClockError>>);
impl TestClock {
    fn new() -> Self {
        Self(Mutex::new(Ok(reading(EPOCH, 1))))
    }
    fn set(&self, value: Result<ClockReading, ClockError>) -> TestResult {
        *self.0.lock().map_err(|_| "test clock poisoned")? = value;
        Ok(())
    }
}
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}
fn reading(ms: u64, tick: u64) -> ClockReading {
    ClockReading::new(UnixMillis::new(ms), MonotonicInstant::from_nanos(tick))
}
fn at_epoch() -> TestResult<Fixture> {
    let mut fixture = fixture()?;
    let mut body = fixture.authorization.authorization.clone();
    body.not_before_unix_ms = EPOCH;
    body.expires_at_unix_ms = EPOCH + 100;
    fixture.authorization = SignedCallerDispatchAuthorizationV1::sign(body, &fixture.kernel)?;
    Ok(fixture)
}
fn provision(fixture: &Fixture, clock: Arc<TestClock>) -> TestResult<SqliteCallerExecutionLedger> {
    Ok(SqliteCallerExecutionLedger::provision_with_clock(
        &fixture.path(),
        fixture.authorization.authorization.executor.clone(),
        2,
        clock,
    )?)
}

#[test]
fn injected_epoch_owns_claim_report_expiry_and_restart() -> TestResult {
    let fixture = at_epoch()?;
    let clock = Arc::new(TestClock::new());
    let ledger = provision(&fixture, clock.clone())?;
    let effects = AtomicUsize::new(0);
    let first = fixture.execute(&ledger, || {
        effects.fetch_add(1, Ordering::SeqCst);
        clock
            .set(Ok(reading(EPOCH + 1, 2)))
            .map_err(|e| KernelError::Internal(e.to_string()))?;
        returned()
    })?;
    assert_eq!(first.report.execution_started_at_unix_ms, EPOCH);
    assert_eq!(first.report.completed_at_unix_ms, EPOCH + 1);
    drop(ledger);
    clock.set(Ok(reading(EPOCH + 100, 3)))?;
    let ledger = SqliteCallerExecutionLedger::open_with_clock(
        &fixture.path(),
        fixture.authorization.authorization.executor.clone(),
        clock.clone(),
    )?;
    let replay = fixture.execute(&ledger, || {
        effects.fetch_add(1, Ordering::SeqCst);
        returned()
    })?;
    assert_eq!(first.canonical_bytes()?, replay.canonical_bytes()?);
    let unused = at_epoch()?;
    let unused_ledger = provision(&unused, clock)?;
    assert!(matches!(
        unused.execute(&unused_ledger, || {
            effects.fetch_add(1, Ordering::SeqCst);
            returned()
        }),
        Err(CallerExecutionLedgerError::Authentication(
            CallerDeliveryError::Expired
        ))
    ));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn clock_faults_deny_report_replay_and_preserve_durable_custody() -> TestResult {
    for fault in [
        Err(ClockError::Unavailable),
        Ok(reading(EPOCH - 1, 2)),
        Ok(reading(EPOCH, 0)),
    ] {
        let fixture = at_epoch()?;
        let clock = Arc::new(TestClock::new());
        let ledger = provision(&fixture, clock.clone())?;
        let first = fixture.execute(&ledger, returned)?;
        clock.set(fault)?;
        let effects = AtomicUsize::new(0);
        assert!(matches!(
            fixture.execute(&ledger, || {
                effects.fetch_add(1, Ordering::SeqCst);
                returned()
            }),
            Err(CallerExecutionLedgerError::Storage(_))
        ));
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        drop(ledger);
        if !matches!(fault, Ok(value) if value.unix_millis().get() == EPOCH) {
            assert!(matches!(
                SqliteCallerExecutionLedger::open_with_clock(
                    &fixture.path(),
                    fixture.authorization.authorization.executor.clone(),
                    clock.clone(),
                ),
                Err(CallerExecutionLedgerError::Storage(_))
            ));
        }
        clock.set(Ok(reading(EPOCH + 1, 3)))?;
        let ledger = SqliteCallerExecutionLedger::open_with_clock(
            &fixture.path(),
            fixture.authorization.authorization.executor.clone(),
            clock,
        )?;
        let replay = fixture.execute(&ledger, || {
            effects.fetch_add(1, Ordering::SeqCst);
            returned()
        })?;
        assert_eq!(first.canonical_bytes()?, replay.canonical_bytes()?);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
