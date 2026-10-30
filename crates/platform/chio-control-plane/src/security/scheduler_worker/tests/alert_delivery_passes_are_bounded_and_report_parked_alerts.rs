use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use chio_security_types::clock::{ClockError, ClockReading, FixedClock};
use chio_security_types::ports::{Digest32, RecordId, SecurityAlert, SecurityAlertPort, TenantId};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteSecurityAlertOutboxStore;

use super::{SecurityAlertDelivery, SecurityAlertDeliveryHealth, SECURITY_ALERT_ROWS_PER_PASS};
use crate::security::adapters::{AlertOutboxConfig, SecurityAlertOutbox};

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
    outbox: Arc<SecurityAlertOutbox>,
    backend: Arc<CountingBackend>,
    clock: Arc<CountingClock>,
    delivery: SecurityAlertDelivery,
}

fn fixture(accept: bool, max_attempts: u32) -> DeliveryFixture {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let backend = Arc::new(CountingBackend::new(accept));
    let outbox = Arc::new(
        SqliteSecurityAlertOutboxStore::open(directory.path().join("alerts.sqlite"))
            .and_then(|store| {
                SecurityAlertOutbox::new(
                    Arc::new(store),
                    vec![backend.clone() as Arc<dyn AlertBackend>],
                    AlertOutboxConfig {
                        base_retry_ms: 1_000,
                        max_retry_ms: 60_000,
                        max_attempts,
                    },
                )
            })
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

fn page(outbox: &SecurityAlertOutbox, index: usize) {
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
async fn parked_alerts_remain_parked_after_reopening_with_a_larger_retry_limit() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("alerts.sqlite");
    let refusing = Arc::new(CountingBackend::new(false));
    {
        let outbox = Arc::new(
            SqliteSecurityAlertOutboxStore::open(&path)
                .and_then(|store| {
                    SecurityAlertOutbox::new(
                        Arc::new(store),
                        vec![refusing.clone() as Arc<dyn AlertBackend>],
                        AlertOutboxConfig {
                            base_retry_ms: 1_000,
                            max_retry_ms: 60_000,
                            max_attempts: 1,
                        },
                    )
                })
                .unwrap_or_else(|error| panic!("first outbox: {error}")),
        );
        page(&outbox, 0);
        let delivery = SecurityAlertDelivery::new(outbox, Arc::new(CountingClock::new()));
        delivery.deliver_once().await;
        assert_eq!(delivery.health().parked, 1);
        assert_eq!(refusing.dispatches(), 1);
    }

    let accepting = Arc::new(CountingBackend::new(true));
    let reopened = Arc::new(
        SqliteSecurityAlertOutboxStore::open(&path)
            .and_then(|store| {
                SecurityAlertOutbox::new(
                    Arc::new(store),
                    vec![accepting.clone() as Arc<dyn AlertBackend>],
                    AlertOutboxConfig {
                        base_retry_ms: 1_000,
                        max_retry_ms: 60_000,
                        max_attempts: 3,
                    },
                )
            })
            .unwrap_or_else(|error| panic!("reopened outbox: {error}")),
    );
    let clock = Arc::new(CountingClock::new());
    let delivery = SecurityAlertDelivery::new(reopened, clock.clone());
    delivery.deliver_once().await;
    assert_eq!(
        delivery.health(),
        SecurityAlertDeliveryHealth {
            passes: 1,
            pending: 0,
            parked: 1,
            ..SecurityAlertDeliveryHealth::default()
        }
    );
    assert_eq!(
        accepting.dispatches(),
        0,
        "a larger retry limit must not requeue a parked alert"
    );
    assert_eq!(
        clock.reads(),
        0,
        "only parked alerts need no delivery clock"
    );
}
