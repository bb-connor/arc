use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use chio_security_types::clock::{ClockError, ClockReading, FixedClock};
use chio_security_types::ports::{Digest32, RecordId, SecurityAlert, SecurityAlertPort, TenantId};
use chio_siem::{Alert, AlertBackend, ExportError};

use super::{SecurityAlertDelivery, SecurityAlertDeliveryHealth, SECURITY_ALERT_ROWS_PER_PASS};
use crate::security::adapters::{AlertOutboxConfig, SqliteSiemOutbox};

const NOW_UNIX_MS: u64 = 1_700_000_000_000;

/// Trusted clock that counts reads and can fail the next one.
struct CountingClock {
    reads: AtomicU64,
    fail_next: AtomicBool,
}

impl CountingClock {
    fn new() -> Self {
        Self {
            reads: AtomicU64::new(0),
            fail_next: AtomicBool::new(false),
        }
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Acquire)
    }
}

impl chio_security_types::clock::Clock for CountingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        if self.fail_next.swap(false, Ordering::AcqRel) {
            return Err(ClockError::Unavailable);
        }
        FixedClock::from_millis(NOW_UNIX_MS).read()
    }
}

/// SIEM backend that confirms or refuses every alert and counts dispatches.
struct CountingBackend {
    accept: bool,
    dispatches: AtomicUsize,
}

impl CountingBackend {
    fn new(accept: bool) -> Self {
        Self {
            accept,
            dispatches: AtomicUsize::new(0),
        }
    }

    fn dispatches(&self) -> usize {
        self.dispatches.load(Ordering::Acquire)
    }
}

impl AlertBackend for CountingBackend {
    fn name(&self) -> &str {
        "alert-delivery-counting"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.dispatches.fetch_add(1, Ordering::AcqRel);
            if self.accept {
                Ok(())
            } else {
                Err(ExportError::HttpError("simulated SIEM outage".to_owned()))
            }
        })
    }
}

struct DeliveryFixture {
    _directory: tempfile::TempDir,
    outbox: Arc<SqliteSiemOutbox>,
    backend: Arc<CountingBackend>,
    clock: Arc<CountingClock>,
    delivery: SecurityAlertDelivery,
}

fn fixture(accept: bool, max_attempts: u32) -> DeliveryFixture {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let backend = Arc::new(CountingBackend::new(accept));
    let outbox = Arc::new(
        SqliteSiemOutbox::open(
            directory.path().join("alerts.sqlite"),
            vec![backend.clone() as Arc<dyn AlertBackend>],
            AlertOutboxConfig {
                base_retry_ms: 1_000,
                max_retry_ms: 60_000,
                max_attempts,
            },
        )
        .unwrap_or_else(|error| panic!("alert outbox: {error}")),
    );
    let clock = Arc::new(CountingClock::new());
    let delivery = SecurityAlertDelivery::new(Arc::clone(&outbox), clock.clone());
    DeliveryFixture {
        _directory: directory,
        outbox,
        backend,
        clock,
        delivery,
    }
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

fn page(outbox: &SqliteSiemOutbox, index: usize) {
    let record = |value: String| RecordId::new(value).unwrap_or_else(|error| panic!("{error}"));
    let alert = SecurityAlert {
        tenant_id: TenantId::new("tenant-alert-delivery")
            .unwrap_or_else(|error| panic!("tenant: {error}")),
        event_id: record(format!("alert-delivery-event-{index:03}")),
        idempotency_key: record(format!("alert-delivery-key-{index:03}")),
        occurred_at_unix_ms: NOW_UNIX_MS - 1_000,
        alert_type: record("response_rollback_partial".to_owned()),
        finding_id_hash: digest(41),
        action_id_hash: Some(digest(42)),
        evidence_hash: digest(43),
    };
    outbox
        .page(&alert)
        .unwrap_or_else(|error| panic!("page alert {index}: {error}"));
}

#[tokio::test]
async fn a_delivery_pass_dispatches_at_most_its_bound_of_due_alerts() {
    let fixture = fixture(true, 3);
    let paged = SECURITY_ALERT_ROWS_PER_PASS + 4;
    for index in 0..paged {
        page(&fixture.outbox, index);
    }

    fixture.delivery.deliver_once().await;
    let first = fixture.delivery.health();
    let first_dispatches = fixture.backend.dispatches();
    fixture.delivery.deliver_once().await;
    let second = fixture.delivery.health();

    assert_eq!(first_dispatches, SECURITY_ALERT_ROWS_PER_PASS);
    assert_eq!(
        first,
        SecurityAlertDeliveryHealth {
            passes: 1,
            delivered: 16,
            failed_attempts: 0,
            pending: 4,
            parked: 0,
            last_error: None,
        }
    );
    assert_eq!(fixture.backend.dispatches(), paged);
    assert_eq!(
        second,
        SecurityAlertDeliveryHealth {
            passes: 2,
            delivered: 20,
            failed_attempts: 0,
            pending: 0,
            parked: 0,
            last_error: None,
        }
    );
}

#[tokio::test]
async fn an_exhausted_alert_is_reported_parked_and_never_dispatched_again() {
    let fixture = fixture(false, 1);
    page(&fixture.outbox, 0);

    fixture.delivery.deliver_once().await;
    let parked = fixture.delivery.health();
    let reads_after_parking = fixture.clock.reads();
    fixture.delivery.deliver_once().await;

    assert_eq!(
        parked,
        SecurityAlertDeliveryHealth {
            passes: 1,
            delivered: 0,
            failed_attempts: 1,
            pending: 0,
            parked: 1,
            last_error: None,
        }
    );
    assert_eq!(fixture.backend.dispatches(), 1);
    assert_eq!(
        fixture.clock.reads(),
        reads_after_parking,
        "a pass with nothing pending must not read the clock"
    );
    assert_eq!(fixture.delivery.health().parked, 1);
    assert_eq!(
        fixture
            .delivery
            .backlog()
            .unwrap_or_else(|error| panic!("backlog: {error}"))
            .parked,
        1
    );
}

#[tokio::test]
async fn a_clock_failure_is_recorded_and_the_next_pass_clears_it() {
    let fixture = fixture(true, 3);
    page(&fixture.outbox, 0);
    fixture.clock.fail_next.store(true, Ordering::Release);

    fixture.delivery.deliver_once().await;
    let failed = fixture.delivery.health();
    fixture.delivery.deliver_once().await;
    let recovered = fixture.delivery.health();

    assert_eq!(failed.passes, 1);
    assert_eq!(failed.delivered, 0);
    assert_eq!(
        failed.last_error,
        Some(chio_security_types::ports::PortError::from(ClockError::Unavailable).to_string())
    );
    assert_eq!(fixture.backend.dispatches(), 1);
    assert_eq!(
        recovered,
        SecurityAlertDeliveryHealth {
            passes: 2,
            delivered: 1,
            failed_attempts: 0,
            pending: 0,
            parked: 0,
            last_error: None,
        }
    );
}

#[tokio::test]
async fn alert_delivery_makes_progress_while_a_tick_is_parked() {
    use crate::security::scheduler_worker::tests::BlockingWorkerPort;
    use crate::security::scheduler_worker::{
        ProductionResponseWorker, ProductionResponseWorkerLoopConfig,
    };
    use std::time::Duration;

    let fixture = fixture(true, 3);
    let delivery = Arc::new(SecurityAlertDelivery::new(
        Arc::clone(&fixture.outbox),
        fixture.clock.clone(),
    ));
    let port = Arc::new(BlockingWorkerPort::new());
    let worker = Arc::new(
        ProductionResponseWorker::new_with_alert_delivery(
            Arc::clone(&port) as Arc<dyn crate::security::scheduler_worker::ResponseWorkerPort>,
            Some(Arc::clone(&delivery)),
        )
        .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let mut handle = worker
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("start: {error}"));
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("publication: {error}"));
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("readiness: {error}"));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !port.tick_in_flight.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("tick did not park"));

    let passes_when_parked = delivery.health().passes;
    tokio::time::timeout(Duration::from_secs(5), async {
        while delivery.health().passes < passes_when_parked.saturating_add(2) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("alert delivery stalled behind the parked tick"));
    assert!(port.tick_in_flight.load(Ordering::Acquire));

    port.release();
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
}
