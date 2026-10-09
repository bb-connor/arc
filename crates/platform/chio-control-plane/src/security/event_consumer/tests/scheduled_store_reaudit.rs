use super::*;
use std::sync::atomic::{AtomicU8, AtomicUsize};

const NONE: u8 = 0;
const INTEGRITY: u8 = 1;
const UNAVAILABLE: u8 = 2;

struct FaultableBatchStore {
    inner: Arc<SqliteSecurityStateStore>,
    audits: AtomicUsize,
    fault: AtomicU8,
}

impl AttestedFindingBatchStore for FaultableBatchStore {
    fn ensure_attested_finding_batches_ready(&self) -> PortResult<()> {
        self.audits.fetch_add(1, Ordering::AcqRel);
        match self.fault.load(Ordering::Acquire) {
            INTEGRITY => Err(PortError::integrity_failure()),
            UNAVAILABLE => Err(PortError::unavailable()),
            _ => self.inner.ensure_attested_finding_batches_ready(),
        }
    }

    fn publish_attested_finding_batch(
        &self,
        publication: &AttestedFindingBatchPublication,
    ) -> PortResult<CreateOutcome> {
        self.inner.publish_attested_finding_batch(publication)
    }

    fn load_attested_finding_batch(
        &self,
        key: &AttestedFindingBatchKey,
    ) -> PortResult<Option<AttestedFindingBatchPublication>> {
        self.inner.load_attested_finding_batch(key)
    }
}

struct Fixture {
    planner: DurableAttestedFindingBatchPlanner,
    batches: Arc<FaultableBatchStore>,
    clock: Arc<MutableClock>,
    _directory: tempfile::TempDir,
}

const INTERVAL_MS: u64 = 60_000;

fn fixture() -> Fixture {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("scheduled-reaudit.sqlite"))
            .unwrap_or_else(|error| panic!("reaudit store: {error}")),
    );
    let batches = Arc::new(FaultableBatchStore {
        inner: Arc::clone(&store),
        audits: AtomicUsize::new(0),
        fault: AtomicU8::new(NONE),
    });
    let clock = Arc::new(MutableClock::new(10_000));
    let planner = DurableAttestedFindingBatchPlanner::new(
        Arc::clone(&batches) as Arc<dyn AttestedFindingBatchStore>,
        store as Arc<dyn AttestedFindingResponseOutboxStore>,
        Arc::new(ReadyFindingAuthority),
        Arc::new(RecordingResponsePolicy),
        Arc::new(RecordingResponseCoordinator::default()),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .and_then(|planner| planner.with_store_audit_interval_ms(INTERVAL_MS))
    .unwrap_or_else(|error| panic!("reaudit planner: {error}"));
    Fixture {
        planner,
        batches,
        clock,
        _directory: directory,
    }
}

struct ReadyFindingAuthority;

impl ActiveResponseFindingAuthority for ReadyFindingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        Ok(())
    }

    fn load_correlated_finding(
        &self,
        _: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        Ok(None)
    }
}

fn audits(fixture: &Fixture) -> usize {
    fixture.batches.audits.load(Ordering::Acquire)
}

fn kind(result: PortResult<()>) -> Option<PortErrorKind> {
    result.err().map(|error| error.kind())
}

#[test]
fn the_reaudit_runs_when_the_interval_elapses_and_not_before() {
    let fixture = fixture();
    let startup = audits(&fixture);
    fixture.clock.set(10_000 + INTERVAL_MS - 1);
    fixture
        .planner
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("pass before the interval: {error}"));
    assert_eq!(audits(&fixture), startup);

    fixture.clock.set(10_000 + INTERVAL_MS);
    fixture
        .planner
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("pass at the interval: {error}"));
    assert_eq!(audits(&fixture), startup + 1);

    fixture
        .planner
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("pass right after a re-audit: {error}"));
    assert_eq!(audits(&fixture), startup + 1);
}

#[test]
fn readiness_probes_never_trigger_the_scheduled_reaudit() {
    let fixture = fixture();
    let startup = audits(&fixture);
    fixture.clock.set(10_000 + 10 * INTERVAL_MS);
    for _ in 0..25 {
        fixture
            .planner
            .ensure_ready()
            .unwrap_or_else(|error| panic!("planner must be ready: {error}"));
    }
    assert_eq!(audits(&fixture), startup);
}

#[test]
fn corruption_after_a_passing_audit_closes_readiness_at_the_next_reaudit_and_recovers() {
    let fixture = fixture();
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("planner must be ready: {error}"));
    fixture.batches.fault.store(INTEGRITY, Ordering::Release);
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("verdict is still the recorded pass: {error}"));

    fixture.clock.set(10_000 + INTERVAL_MS);
    assert_eq!(
        kind(fixture.planner.resume_incomplete_pass(1).map(|_| ())),
        Some(PortErrorKind::IntegrityFailure)
    );
    assert_eq!(
        kind(fixture.planner.ensure_ready()),
        Some(PortErrorKind::IntegrityFailure)
    );
    assert_eq!(
        kind(fixture.planner.ensure_recovery_ready()),
        Some(PortErrorKind::IntegrityFailure)
    );

    fixture.batches.fault.store(NONE, Ordering::Release);
    fixture.clock.set(10_000 + 2 * INTERVAL_MS);
    fixture
        .planner
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("clean re-audit must pass: {error}"));
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("passing re-audit must reopen readiness: {error}"));
}

#[test]
fn an_unavailable_store_during_reaudit_records_a_failed_verdict() {
    let fixture = fixture();
    fixture.batches.fault.store(UNAVAILABLE, Ordering::Release);
    fixture.clock.set(10_000 + INTERVAL_MS);
    assert_eq!(
        kind(fixture.planner.resume_incomplete_pass(1).map(|_| ())),
        Some(PortErrorKind::Unavailable)
    );
    assert_eq!(
        kind(fixture.planner.ensure_ready()),
        Some(PortErrorKind::Unavailable)
    );
}

#[test]
fn the_audit_interval_rejects_zero_and_excessive_values() {
    for interval_ms in [0, 86_400_001] {
        let rejected = fixture().planner.with_store_audit_interval_ms(interval_ms);
        assert_eq!(
            rejected.err().map(|error| error.kind()),
            Some(PortErrorKind::InvalidData)
        );
    }
}
