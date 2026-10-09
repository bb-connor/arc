use super::*;
use chio_security_types::ports::{ResponseSchedulerStore, SchedulerRetryState, SchedulerWorkKey};
use chio_security_types::{ResponseMutationRecord, ResponseRollbackOutcome, ResponseSnapshot};
use std::sync::Mutex;
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

const LONG_TTL_MS: u64 = 60_000;
const MIN_REMAINING_TTL_MS: u64 = 5_000;
const WORKER_TICK_INTERVAL: Duration = Duration::from_secs(2);
/// Longer than the teardown's bounded fault attempts at its retry interval.
const HEALTHY_WAIT: Duration = Duration::from_secs(8);
/// Worker ticks that may begin from a TTL expiry until its cleanup completes:
/// the first tick to read the expired trusted clock lifts the overlay, and the
/// teardown observes the lift and stops its worker before the tick after that.
const EXPIRY_CLEANUP_TICKS: u64 = 2;
const ATTEMPTS_BEFORE_PARK: usize = 50;
const PARK_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(30);
const PARKED_AUDIT: &str = "active_defense_teardown_cleanup_parked";
const DRAIN_RETRY_AUDIT: &str = "active_defense_detached_pre_stop_drain_retry";
const ROLLBACK_PARTIAL_RETRY: &str = "response.rollback_partial";
/// A durable typed refusal of every overlay contribution removal. Apply and
/// every read path are untouched.
const REFUSE_OVERLAY_ROLLBACK: &str = "CREATE TRIGGER test_refuse_overlay_rollback \
     BEFORE DELETE ON security_effect_contributions \
     BEGIN SELECT RAISE(ABORT, 'injected overlay rollback refusal'); END;";

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

    fn now_unix_ms(&self) -> u64 {
        self.fixture
            .clock
            .read_now_unix_ms()
            .unwrap_or_else(|error| panic!("fixture clock: {error}"))
    }

    fn remaining_ttl_ms(&self) -> u64 {
        self.expires_at_unix_ms.saturating_sub(self.now_unix_ms())
    }

    /// Advances the trusted clock with wall time from the expiry instant.
    fn follow_wall_clock_after_expiry(&self, expired_at: Instant) {
        let elapsed_ms = u64::try_from(expired_at.elapsed().as_millis())
            .unwrap_or_else(|error| panic!("elapsed since expiry: {error}"));
        self.fixture.clock.set(
            self.expires_at_unix_ms
                .saturating_add(1)
                .saturating_add(elapsed_ms),
        );
    }

    fn tenant_and_action(&self) -> (TenantId, ActionId) {
        (
            TenantId::new("tenant-host-lifecycle")
                .unwrap_or_else(|error| panic!("tenant: {error}")),
            ActionId::new("host-lifecycle-ttl-action")
                .unwrap_or_else(|error| panic!("action: {error}")),
        )
    }

    fn response(&self) -> ResponseSnapshot {
        let (tenant_id, action_id) = self.tenant_and_action();
        let record = self
            .fixture
            .security_store
            .load_plan(&ResponsePlanKey {
                tenant_id,
                action_id,
            })
            .unwrap_or_else(|error| panic!("load response: {error}"))
            .unwrap_or_else(|| panic!("response is missing"));
        decode_response_record(&record).unwrap_or_else(|error| panic!("decode response: {error}"))
    }

    fn scheduler_retry(&self) -> Option<SchedulerRetryState> {
        let (tenant_id, action_id) = self.tenant_and_action();
        self.fixture
            .security_store
            .load_retry(&SchedulerWorkKey {
                tenant_id,
                action_id,
            })
            .unwrap_or_else(|error| panic!("load scheduler retry: {error}"))
    }

    fn expire(&self) {
        self.fixture
            .clock
            .set(self.expires_at_unix_ms.saturating_add(1));
    }
}

fn rollback_failure_codes(response: &ResponseSnapshot) -> Vec<String> {
    response
        .mutations
        .as_slice()
        .iter()
        .filter_map(|mutation| match mutation {
            ResponseMutationRecord::Rollback(record) => match &record.outcome {
                ResponseRollbackOutcome::Failed { error_code } => {
                    Some(error_code.as_str().to_string())
                }
                ResponseRollbackOutcome::Requested | ResponseRollbackOutcome::Restored { .. } => {
                    None
                }
            },
            _ => None,
        })
        .collect()
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

/// Polls a teardown that must stay pending after its TTL expired, running
/// `advance_clock` before each poll, until `done` holds or `limit` passes.
async fn hold_expired<F: Future<Output = u32>>(
    teardown: &mut Pin<&mut F>,
    limit: Duration,
    mut advance_clock: impl FnMut(),
    mut done: impl FnMut() -> bool,
) {
    let started = Instant::now();
    while started.elapsed() < limit && !done() {
        advance_clock();
        tokio::select! {
            attempts = teardown.as_mut() => {
                panic!("teardown finished while the expired overlay was held: attempts={attempts}")
            }
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

/// Polls a teardown that must stay pending after its TTL expired, with the
/// trusted clock following wall time from expiry, until `done` holds or
/// `limit` passes.
async fn hold_after_expiry<F: Future<Output = u32>>(
    teardown: &mut Pin<&mut F>,
    ttl: &LongTtlHost,
    expired_at: Instant,
    limit: Duration,
    done: impl FnMut() -> bool,
) {
    hold_expired(
        teardown,
        limit,
        || ttl.follow_wall_clock_after_expiry(expired_at),
        done,
    )
    .await;
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

    let ticks_before_expiry = worker.health().ticks_attempted;
    ttl.expire();
    let cleanup_started = Instant::now();
    let attempts = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, teardown)
        .await
        .unwrap_or_else(|_| panic!("teardown did not clean up after the TTL expired"));
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_ticks = worker
        .health()
        .ticks_attempted
        .saturating_sub(ticks_before_expiry);

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
        cleanup_ticks <= EXPIRY_CLEANUP_TICKS,
        "cleanup after TTL expiry spanned {cleanup_ticks} worker ticks ({cleanup_elapsed:?})"
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
    let waiting_worker = Arc::clone(waiting_host.orchestrator().worker());
    let expiring_worker = Arc::clone(expiring_host.orchestrator().worker());
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

    let expiring_ticks_before = expiring_worker.health().ticks_attempted;
    expiring.expire();
    let expiring_started = Instant::now();
    let expiring_released = released_within(&expiring, HOST_LIFECYCLE_TEST_TIMEOUT).await;
    let expiring_elapsed = expiring_started.elapsed();
    let expiring_ticks = expiring_worker
        .health()
        .ticks_attempted
        .saturating_sub(expiring_ticks_before);
    let waiting_still_held = waiting.fixture.registry.snapshot().is_some()
        && waiting.fixture.has_active_overlay_contributions();
    let waiting_ticks_before = waiting_worker.health().ticks_attempted;
    waiting.expire();
    let waiting_started = Instant::now();
    let waiting_released = released_within(&waiting, HOST_LIFECYCLE_TEST_TIMEOUT).await;
    let waiting_elapsed = waiting_started.elapsed();
    let waiting_ticks = waiting_worker
        .health()
        .ticks_attempted
        .saturating_sub(waiting_ticks_before);

    assert!(
        both_held,
        "a teardown released its reservation while its TTL overlay was live"
    );
    assert!(
        remaining_ttl_ms > MIN_REMAINING_TTL_MS,
        "the TTLs were not live for the whole wait: remaining_ttl_ms={remaining_ttl_ms}"
    );
    assert!(
        expiring_released && expiring_ticks <= EXPIRY_CLEANUP_TICKS,
        "the first expiry was not cleaned up promptly beside a waiting teardown: released={expiring_released} after {expiring_ticks} worker ticks ({expiring_elapsed:?})"
    );
    assert!(
        waiting_still_held,
        "the waiting teardown released before its own TTL expired"
    );
    assert!(
        waiting_released && waiting_ticks <= EXPIRY_CLEANUP_TICKS,
        "the second expiry was not cleaned up promptly: released={waiting_released} after {waiting_ticks} worker ticks ({waiting_elapsed:?})"
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

#[tokio::test]
async fn expired_overlay_whose_rollback_keeps_failing_spends_the_fault_budget() {
    let mut faulted = LongTtlHost::new();
    // Retries fall due one second after each failed attempt, and the operator
    // is paged once failures have persisted for two seconds of trusted time.
    let policy = &mut faulted
        .fixture
        .config
        .active_defense
        .scheduler
        .scheduler_policy;
    policy.base_backoff_ms = 1_000;
    policy.max_backoff_ms = 1_000;
    policy.operator_page_threshold_ms = 2_000;
    let healthy = LongTtlHost::new();
    let faulted_host = faulted.start().await;
    let healthy_host = healthy.start().await;
    let worker = Arc::clone(faulted_host.orchestrator().worker());
    let healthy_worker = Arc::clone(healthy_host.orchestrator().worker());
    let connection = rusqlite::Connection::open(&faulted.fixture.security_path)
        .unwrap_or_else(|error| panic!("open rollback fault connection: {error}"));
    connection
        .execute_batch(REFUSE_OVERLAY_ROLLBACK)
        .unwrap_or_else(|error| panic!("inject overlay rollback refusal: {error}"));
    let capture = AuditCapture::default();
    let _subscriber = tracing::subscriber::set_default(Registry::default().with(capture.clone()));

    let mut teardown = Box::pin(faulted_host.run_detached_teardown_inline_for_test());
    drop(healthy_host);
    faulted.expire();
    let expired_at = Instant::now();
    hold_after_expiry(
        &mut teardown.as_mut(),
        &faulted,
        expired_at,
        PARK_OBSERVATION_TIMEOUT,
        || {
            rollback_failure_codes(&faulted.response()).len() >= 2
                && faulted.scheduler_retry().is_some_and(|retry| {
                    retry.health_event_id.is_some()
                        && retry.last_error.as_str() == ROLLBACK_PARTIAL_RETRY
                })
        },
    )
    .await;
    let durable_failure_after = expired_at.elapsed();

    let healthy_ticks_before = healthy_worker.health().ticks_attempted;
    healthy.expire();
    let healthy_started = Instant::now();
    hold_after_expiry(
        &mut teardown.as_mut(),
        &faulted,
        expired_at,
        HOST_LIFECYCLE_TEST_TIMEOUT,
        || healthy.fixture.registry.snapshot().is_none(),
    )
    .await;
    let healthy_elapsed = healthy_started.elapsed();
    let healthy_ticks = healthy_worker
        .health()
        .ticks_attempted
        .saturating_sub(healthy_ticks_before);
    let healthy_released = healthy.fixture.registry.snapshot().is_none()
        && !healthy.fixture.has_active_overlay_contributions();

    hold_after_expiry(
        &mut teardown.as_mut(),
        &faulted,
        expired_at,
        HEALTHY_WAIT,
        || capture.parked(),
    )
    .await;
    // Every due retry durably passes through RollingBack. Hold trusted time so
    // no further retry falls due, and sample once the worker has completed a
    // tick begun after the hold, when no rollback attempt can be in flight.
    let started_before_hold = worker.health().last_tick_started_sequence;
    let worker_settled = || worker.health().last_tick_completed_sequence > started_before_hold;
    hold_expired(
        &mut teardown.as_mut(),
        HOST_LIFECYCLE_TEST_TIMEOUT,
        || {},
        worker_settled,
    )
    .await;
    let settled = worker_settled();
    let response = faulted.response();
    let failure_codes = rollback_failure_codes(&response);
    let retry = faulted.scheduler_retry();
    let now_unix_ms = faulted.now_unix_ms();
    let health = worker.health();
    let overlay_held = faulted.fixture.has_active_overlay_contributions();
    let owner_held = faulted.fixture.registry.snapshot().is_some();
    let parked = capture.parked();
    let drain_faults = capture.count(tracing::Level::WARN, DRAIN_RETRY_AUDIT);
    let fault_audits = capture.snapshot().len();
    drop(teardown);

    assert!(
        settled,
        "the recovery worker completed no tick once trusted time was held: {health:?}"
    );
    assert!(
        now_unix_ms > response.plan.expires_at_unix_ms,
        "the TTL had not expired: now={now_unix_ms} expires={}",
        response.plan.expires_at_unix_ms
    );
    assert_eq!(
        response.state,
        ResponseState::RollbackPartial,
        "the expired response did not hold a durable rollback failure after {durable_failure_after:?}"
    );
    assert!(
        failure_codes.len() >= 2
            && failure_codes
                .iter()
                .all(|code| code.as_str() == PortError::conflict().code().as_str()),
        "the rollback failure was not the injected typed refusal: {failure_codes:?}"
    );
    let retry = retry.unwrap_or_else(|| {
        panic!("the scheduler retry evidence was not retained: worker={health:?}")
    });
    assert!(
        retry.attempts >= 2
            && retry.last_error.as_str() == ROLLBACK_PARTIAL_RETRY
            && retry.health_event_id.is_some(),
        "the scheduler retry and page evidence was not retained: {retry:?}"
    );
    assert_eq!(
        health.lifecycle,
        ResponseWorkerLifecycle::Ready,
        "worker ticks did not keep returning cleanly: {health:?}"
    );
    assert!(
        healthy_released && healthy_ticks <= EXPIRY_CLEANUP_TICKS,
        "a healthy second teardown did not progress beside the failing rollback: released={healthy_released} after {healthy_ticks} worker ticks ({healthy_elapsed:?})"
    );
    assert!(
        overlay_held && owner_held,
        "the failing teardown released its overlay or ownership: overlay_held={overlay_held} owner_held={owner_held}"
    );
    assert!(
        parked && drain_faults >= ATTEMPTS_BEFORE_PARK,
        "an expired overlay whose rollback keeps failing was paced as an expected wait: parked={parked} drain_faults={drain_faults} fault_audits={fault_audits} retry_attempts={} rollback_failures={}",
        retry.attempts,
        failure_codes.len()
    );
}
