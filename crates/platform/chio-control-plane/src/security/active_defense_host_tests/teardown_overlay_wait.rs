use super::*;
use std::sync::Mutex;
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

const LONG_TTL_MS: u64 = 60_000;
const MIN_REMAINING_TTL_MS: u64 = 5_000;
const WORKER_TICK_INTERVAL: Duration = Duration::from_secs(2);
/// Longer than the teardown's bounded fault attempts at its retry interval.
const HEALTHY_WAIT: Duration = Duration::from_secs(8);
const EXPIRY_CLEANUP_BOUND: Duration = Duration::from_secs(4);
const ATTEMPTS_BEFORE_PARK: usize = 50;
const PARK_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(30);
const PARKED_AUDIT: &str = "active_defense_teardown_cleanup_parked";
const DRAIN_RETRY_AUDIT: &str = "active_defense_detached_pre_stop_drain_retry";

#[derive(Clone, Default)]
struct AuditCapture {
    faults: Arc<Mutex<Vec<(tracing::Level, String)>>>,
}

impl AuditCapture {
    fn snapshot(&self) -> Vec<(tracing::Level, String)> {
        self.faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn count(&self, level: tracing::Level, audit_fault: &str) -> usize {
        self.snapshot()
            .iter()
            .filter(|(recorded, fault)| *recorded == level && fault == audit_fault)
            .count()
    }

    fn parked(&self) -> bool {
        self.count(tracing::Level::ERROR, PARKED_AUDIT) > 0
    }
}

struct AuditField(Option<String>);

impl Visit for AuditField {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "audit_fault" {
            self.0 = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "audit_fault" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for AuditCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut field = AuditField(None);
        event.record(&mut field);
        if let Some(fault) = field.0 {
            self.faults
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((*event.metadata().level(), fault));
        }
    }
}

/// A host fixture holding one valid containment overlay with a long TTL.
struct LongTtlHost {
    fixture: HostFixture,
    expires_at_unix_ms: u64,
    origin: Instant,
}

impl LongTtlHost {
    fn new() -> Self {
        let mut fixture = HostFixture::new();
        fixture.config.worker_loop.tick_interval = WORKER_TICK_INTERVAL;
        let expires_at_unix_ms = fixture.install_containment_plan_with_ttl(LONG_TTL_MS);
        Self {
            fixture,
            expires_at_unix_ms,
            origin: Instant::now(),
        }
    }

    async fn start(&self) -> ProductionActiveDefenseHost {
        ProductionActiveDefenseHost::start(
            Arc::clone(&self.fixture.registry),
            self.fixture.config.clone(),
        )
        .await
        .unwrap_or_else(|error| panic!("start host: {error}"))
    }

    /// Advances the trusted clock with wall time from installation.
    fn follow_wall_clock(&self) {
        let elapsed_ms = u64::try_from(self.origin.elapsed().as_millis())
            .unwrap_or_else(|error| panic!("elapsed wait: {error}"));
        self.fixture.clock.set(
            self.expires_at_unix_ms
                .saturating_sub(LONG_TTL_MS)
                .saturating_add(elapsed_ms),
        );
    }

    fn remaining_ttl_ms(&self) -> u64 {
        let now_unix_ms = self
            .fixture
            .clock
            .read_now_unix_ms()
            .unwrap_or_else(|error| panic!("fixture clock: {error}"));
        self.expires_at_unix_ms.saturating_sub(now_unix_ms)
    }

    fn expire(&self) {
        self.fixture
            .clock
            .set(self.expires_at_unix_ms.saturating_add(1));
    }
}

async fn released_within(ttl: &LongTtlHost, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, ttl.fixture.registry.wait_until_vacant())
        .await
        .is_ok_and(|vacancy| vacancy.is_ok())
}

/// Polls a teardown that must keep waiting for the live TTL until `done`
/// holds or `limit` passes.
async fn hold_while_ttl_live<F: Future<Output = u32>>(
    teardown: &mut Pin<&mut F>,
    ttl: &LongTtlHost,
    limit: Duration,
    mut done: impl FnMut() -> bool,
) {
    let started = Instant::now();
    while started.elapsed() < limit && !done() {
        ttl.follow_wall_clock();
        tokio::select! {
            attempts = teardown.as_mut() => {
                panic!("teardown finished while the TTL overlay was held: attempts={attempts}")
            }
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

#[tokio::test]
async fn healthy_ttl_wait_spends_no_fault_budget_and_cleans_up_once_expired() {
    let ttl = LongTtlHost::new();
    let host = ttl.start().await;
    let worker = Arc::clone(host.orchestrator().worker());
    let capture = AuditCapture::default();
    let _subscriber = tracing::subscriber::set_default(Registry::default().with(capture.clone()));
    let ticks_at_start = worker.health().ticks_completed;

    let teardown = host.run_detached_teardown_inline_for_test();
    tokio::pin!(teardown);
    let wait_started = Instant::now();
    hold_while_ttl_live(&mut teardown, &ttl, HEALTHY_WAIT, || capture.parked()).await;
    let waited = wait_started.elapsed();
    let faults_during_wait = capture.snapshot();
    let parked = capture.parked();
    let health = worker.health();
    let overlay_held = ttl.fixture.has_active_overlay_contributions();
    let remaining_ttl_ms = ttl.remaining_ttl_ms();

    ttl.expire();
    let cleanup_started = Instant::now();
    let attempts = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, teardown)
        .await
        .unwrap_or_else(|_| panic!("teardown did not clean up after the TTL expired"));
    let cleanup_elapsed = cleanup_started.elapsed();

    assert!(
        health.lifecycle == ResponseWorkerLifecycle::Ready
            && health.last_error.is_none()
            && health.ticks_completed > ticks_at_start,
        "the recovery worker was not healthy throughout the wait: ticks_at_start={ticks_at_start} {health:?}"
    );
    assert!(overlay_held, "the TTL overlay was not held during the wait");
    assert!(
        remaining_ttl_ms > MIN_REMAINING_TTL_MS,
        "the TTL was not live for the whole wait: remaining_ttl_ms={remaining_ttl_ms}"
    );
    assert!(
        !parked && faults_during_wait.is_empty() && attempts == 0,
        "a healthy TTL wait spent the fault budget: waited={waited:?} attempts={attempts} parked={parked} fault_audits={} first={:?}",
        faults_during_wait.len(),
        faults_during_wait.first()
    );
    assert_eq!(capture.snapshot(), Vec::new());
    assert!(
        cleanup_elapsed < EXPIRY_CLEANUP_BOUND,
        "cleanup after TTL expiry took {cleanup_elapsed:?}"
    );
    assert!(!ttl.fixture.has_active_overlay_contributions());
    assert!(ttl.fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn two_teardowns_in_healthy_ttl_waits_each_clean_up_on_their_own_expiry() {
    let waiting = LongTtlHost::new();
    let expiring = LongTtlHost::new();
    let waiting_host = waiting.start().await;
    let expiring_host = expiring.start().await;
    drop(waiting_host);
    drop(expiring_host);

    let wait_started = Instant::now();
    while wait_started.elapsed() < HEALTHY_WAIT {
        waiting.follow_wall_clock();
        expiring.follow_wall_clock();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let both_held = [&waiting, &expiring].iter().all(|ttl| {
        ttl.fixture.registry.snapshot().is_some() && ttl.fixture.has_active_overlay_contributions()
    });
    let remaining_ttl_ms = waiting.remaining_ttl_ms().min(expiring.remaining_ttl_ms());

    expiring.expire();
    let expiring_started = Instant::now();
    let expiring_released = released_within(&expiring, HOST_LIFECYCLE_TEST_TIMEOUT).await;
    let expiring_elapsed = expiring_started.elapsed();
    let waiting_still_held = waiting.fixture.registry.snapshot().is_some()
        && waiting.fixture.has_active_overlay_contributions();
    waiting.expire();
    let waiting_started = Instant::now();
    let waiting_released = released_within(&waiting, HOST_LIFECYCLE_TEST_TIMEOUT).await;
    let waiting_elapsed = waiting_started.elapsed();

    assert!(
        both_held,
        "a teardown released its reservation while its TTL overlay was live"
    );
    assert!(
        remaining_ttl_ms > MIN_REMAINING_TTL_MS,
        "the TTLs were not live for the whole wait: remaining_ttl_ms={remaining_ttl_ms}"
    );
    assert!(
        expiring_released && expiring_elapsed < EXPIRY_CLEANUP_BOUND,
        "the first expiry was not cleaned up promptly beside a waiting teardown: released={expiring_released} after {expiring_elapsed:?}"
    );
    assert!(
        waiting_still_held,
        "the waiting teardown released before its own TTL expired"
    );
    assert!(
        waiting_released && waiting_elapsed < EXPIRY_CLEANUP_BOUND,
        "the second expiry was not cleaned up promptly: released={waiting_released} after {waiting_elapsed:?}"
    );
    assert!(!waiting.fixture.has_active_overlay_contributions());
    assert!(!expiring.fixture.has_active_overlay_contributions());
}

#[tokio::test]
async fn store_fault_during_a_ttl_wait_still_spends_the_fault_budget_and_parks() {
    let ttl = LongTtlHost::new();
    let host = ttl.start().await;
    let worker = Arc::clone(host.orchestrator().worker());
    let connection = rusqlite::Connection::open(&ttl.fixture.security_path)
        .unwrap_or_else(|error| panic!("open inventory fault connection: {error}"));
    let capture = AuditCapture::default();
    let _subscriber = tracing::subscriber::set_default(Registry::default().with(capture.clone()));

    let teardown = host.run_detached_teardown_inline_for_test();
    tokio::pin!(teardown);
    hold_while_ttl_live(&mut teardown, &ttl, Duration::from_millis(500), || false).await;
    let faults_before_outage = capture.snapshot();
    // An internal test-owned table name. Only the teardown's overlay
    // inventory reads it while nothing is due.
    connection
        .execute_batch(
            "ALTER TABLE security_egress_restriction_effects RENAME TO unavailable_overlay_inventory",
        )
        .unwrap_or_else(|error| panic!("inject overlay inventory outage: {error}"));
    hold_while_ttl_live(&mut teardown, &ttl, PARK_OBSERVATION_TIMEOUT, || {
        capture.parked()
    })
    .await;
    let health = worker.health();
    let drain_faults_at_park = capture.count(tracing::Level::WARN, DRAIN_RETRY_AUDIT);
    connection
        .execute_batch(
            "ALTER TABLE unavailable_overlay_inventory RENAME TO security_egress_restriction_effects",
        )
        .unwrap_or_else(|error| panic!("restore overlay inventory: {error}"));
    ttl.expire();
    let attempts = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, teardown)
        .await
        .unwrap_or_else(|_| panic!("teardown did not clean up after the store recovered"));

    assert_eq!(faults_before_outage, Vec::new());
    assert_eq!(
        health.lifecycle,
        ResponseWorkerLifecycle::Ready,
        "the store fault was not confined to the teardown inventory: {health:?}"
    );
    assert_eq!(capture.count(tracing::Level::ERROR, PARKED_AUDIT), 1);
    assert_eq!(drain_faults_at_park, ATTEMPTS_BEFORE_PARK);
    assert!(
        usize::try_from(attempts).is_ok_and(|attempts| attempts >= ATTEMPTS_BEFORE_PARK),
        "store faults did not spend the fault budget: attempts={attempts}"
    );
    assert!(!ttl.fixture.has_active_overlay_contributions());
    assert!(ttl.fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn recovery_worker_crash_during_a_ttl_wait_still_spends_the_fault_budget() {
    let ttl = LongTtlHost::new();
    let host = ttl.start().await;
    let primary = Arc::clone(host.orchestrator().worker());
    let capture = AuditCapture::default();
    let _subscriber = tracing::subscriber::set_default(Registry::default().with(capture.clone()));

    let teardown = host.run_detached_teardown_inline_for_test();
    tokio::pin!(teardown);
    hold_while_ttl_live(&mut teardown, &ttl, Duration::from_millis(500), || false).await;
    let faults_before_crash = capture.snapshot();
    ttl.fixture.clock.panic_on_next_worker_read();
    hold_while_ttl_live(&mut teardown, &ttl, PARK_OBSERVATION_TIMEOUT, || {
        capture.count(tracing::Level::WARN, DRAIN_RETRY_AUDIT) > 0
    })
    .await;
    let primary_health = primary.health();
    let recovery_faults = capture.count(tracing::Level::WARN, DRAIN_RETRY_AUDIT);
    hold_while_ttl_live(&mut teardown, &ttl, Duration::from_secs(3), || false).await;
    let faults_after_recovered_wait = capture.count(tracing::Level::WARN, DRAIN_RETRY_AUDIT);
    ttl.expire();
    let attempts = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, teardown)
        .await
        .unwrap_or_else(|_| panic!("teardown did not clean up after recovery"));

    assert_eq!(faults_before_crash, Vec::new());
    assert_eq!(primary_health.lifecycle, ResponseWorkerLifecycle::Failed);
    assert!(
        recovery_faults > 0,
        "a recovery worker crash spent no fault budget"
    );
    assert_eq!(
        faults_after_recovered_wait, recovery_faults,
        "the recovered TTL wait kept spending the fault budget"
    );
    assert_eq!(usize::try_from(attempts).ok(), Some(recovery_faults));
    assert!(!capture.parked());
    assert!(!ttl.fixture.has_active_overlay_contributions());
    assert!(ttl.fixture.registry.snapshot().is_none());
}
