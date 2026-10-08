use super::*;
use crate::security::event_consumer::recovery::PLANNER_LIVENESS_PROBE_TTL_MS;
use std::sync::atomic::AtomicUsize;

struct AuditCountingBatchStore {
    inner: Arc<SqliteSecurityStateStore>,
    audits: AtomicUsize,
    fail: AtomicBool,
}

impl AttestedFindingBatchStore for AuditCountingBatchStore {
    fn ensure_attested_finding_batches_ready(&self) -> PortResult<()> {
        self.audits.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) {
            return Err(PortError::integrity_failure());
        }
        self.inner.ensure_attested_finding_batches_ready()
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

struct LivenessCountingAuthority {
    probes: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
}

impl ActiveResponseFindingAuthority for LivenessCountingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        self.probes.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) {
            return Err(ActiveResponseFindingAuthorityError::Unavailable(
                "authority down".to_string(),
            ));
        }
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

struct Fixture {
    planner: DurableAttestedFindingBatchPlanner,
    batches: Arc<AuditCountingBatchStore>,
    authority_probes: Arc<AtomicUsize>,
    authority_down: Arc<AtomicBool>,
    clock: Arc<MutableClock>,
    _directory: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("planner-readiness.sqlite"))
            .unwrap_or_else(|error| panic!("readiness store: {error}")),
    );
    let batches = Arc::new(AuditCountingBatchStore {
        inner: Arc::clone(&store),
        audits: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let authority_probes = Arc::new(AtomicUsize::new(0));
    let authority_down = Arc::new(AtomicBool::new(false));
    let clock = Arc::new(MutableClock::new(10_000));
    let planner = DurableAttestedFindingBatchPlanner::new(
        Arc::clone(&batches) as Arc<dyn AttestedFindingBatchStore>,
        store as Arc<dyn AttestedFindingResponseOutboxStore>,
        Arc::new(LivenessCountingAuthority {
            probes: Arc::clone(&authority_probes),
            fail: Arc::clone(&authority_down),
        }),
        Arc::new(RecordingResponsePolicy),
        Arc::new(RecordingResponseCoordinator::default()),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .unwrap_or_else(|error| panic!("readiness planner: {error}"));
    Fixture {
        planner,
        batches,
        authority_probes,
        authority_down,
        clock,
        _directory: directory,
    }
}

#[test]
fn passing_startup_audit_makes_the_planner_ready() {
    let fixture = fixture();
    assert_eq!(fixture.batches.audits.load(Ordering::Acquire), 1);
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("planner must be ready: {error}"));
}

#[test]
fn readiness_probes_do_not_rerun_the_full_history_audit() {
    let fixture = fixture();
    let audits_after_startup = fixture.batches.audits.load(Ordering::Acquire);
    for _ in 0..25 {
        fixture
            .planner
            .ensure_ready()
            .unwrap_or_else(|error| panic!("planner must be ready: {error}"));
        fixture
            .planner
            .ensure_recovery_ready()
            .unwrap_or_else(|error| panic!("recovery must be ready: {error}"));
    }
    assert_eq!(
        fixture.batches.audits.load(Ordering::Acquire),
        audits_after_startup
    );
}

#[test]
fn readiness_reuses_a_fresh_dependency_probe_and_refreshes_it_after_the_ttl() {
    let fixture = fixture();
    let before = fixture.authority_probes.load(Ordering::Acquire);
    for _ in 0..10 {
        fixture
            .planner
            .ensure_ready()
            .unwrap_or_else(|error| panic!("planner must be ready: {error}"));
    }
    assert_eq!(fixture.authority_probes.load(Ordering::Acquire), before + 1);
    fixture.clock.set(10_000 + PLANNER_LIVENESS_PROBE_TTL_MS);
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("planner must be ready: {error}"));
    assert_eq!(fixture.authority_probes.load(Ordering::Acquire), before + 2);
}

#[test]
fn a_dependency_failure_is_never_cached_as_ready() {
    let fixture = fixture();
    fixture.clock.set(100_000);
    fixture.authority_down.store(true, Ordering::Release);
    let first = fixture.planner.ensure_ready();
    assert_eq!(
        first.err().map(|error| error.kind()),
        Some(PortErrorKind::Unavailable)
    );
    fixture.authority_down.store(false, Ordering::Release);
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("recovered authority must restore readiness: {error}"));
}

#[test]
fn failed_audit_keeps_readiness_closed_until_a_later_audit_passes() {
    let fixture = fixture();
    fixture.batches.fail.store(true, Ordering::Release);
    let audit = fixture.planner.run_store_audit();
    assert_eq!(
        audit.err().map(|error| error.kind()),
        Some(PortErrorKind::IntegrityFailure)
    );
    let audits_after_failure = fixture.batches.audits.load(Ordering::Acquire);

    let ready = fixture.planner.ensure_ready();
    assert_eq!(
        ready.err().map(|error| error.kind()),
        Some(PortErrorKind::IntegrityFailure)
    );
    let recovery = fixture.planner.ensure_recovery_ready();
    assert_eq!(
        recovery.err().map(|error| error.kind()),
        Some(PortErrorKind::IntegrityFailure)
    );
    assert_eq!(
        fixture.batches.audits.load(Ordering::Acquire),
        audits_after_failure
    );

    fixture.batches.fail.store(false, Ordering::Release);
    fixture
        .planner
        .run_store_audit()
        .unwrap_or_else(|error| panic!("clean audit must pass: {error}"));
    fixture
        .planner
        .ensure_ready()
        .unwrap_or_else(|error| panic!("passing audit must reopen readiness: {error}"));
}

#[test]
fn bootstrap_readiness_reruns_the_full_audit() {
    let fixture = fixture();
    let before = fixture.batches.audits.load(Ordering::Acquire);
    fixture
        .planner
        .ensure_bootstrap_ready()
        .unwrap_or_else(|error| panic!("bootstrap must be ready: {error}"));
    assert_eq!(fixture.batches.audits.load(Ordering::Acquire), before + 1);
}
