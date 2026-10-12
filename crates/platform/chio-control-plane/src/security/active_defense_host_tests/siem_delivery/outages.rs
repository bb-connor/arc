use super::*;

struct PanickingAlertBackend {
    entered: AtomicBool,
    panics: AtomicBool,
}

impl Default for PanickingAlertBackend {
    fn default() -> Self {
        Self {
            entered: AtomicBool::new(false),
            panics: AtomicBool::new(true),
        }
    }
}

impl AlertBackend for PanickingAlertBackend {
    fn name(&self) -> &str {
        "active-defense-host-panicking"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.store(true, Ordering::Release);
            if self.panics.load(Ordering::Acquire) {
                panic!("injected SIEM backend panic");
            }
            Ok(())
        })
    }
}

#[derive(Default)]
struct ReleasedAlertBackend {
    entered: AtomicBool,
    returned: AtomicBool,
    release: tokio::sync::Notify,
}

impl AlertBackend for ReleasedAlertBackend {
    fn name(&self) -> &str {
        "active-defense-host-released"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.store(true, Ordering::Release);
            self.release.notified().await;
            self.returned.store(true, Ordering::Release);
            Ok(())
        })
    }
}

async fn wait_for_signal(signal: &AtomicBool) {
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !signal.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("backend did not reach its expected phase"));
}

#[tokio::test]
async fn a_panicking_siem_backend_does_not_kill_containment_expiry() {
    let mut fixture = HostFixture::new();
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("alert tempdir: {error}"));
    let backend = Arc::new(PanickingAlertBackend::default());
    install_alert_outbox(
        &mut fixture,
        &directory.path().join("panicking-alerts.sqlite"),
        backend.clone(),
        3,
    );
    let expires_at = fixture.install_ttl_containment_plan();
    let now = fixture
        .clock
        .read_now_unix_ms()
        .unwrap_or_else(|error| panic!("fixture clock: {error}"));
    apply_escalation_plan(&fixture, now);
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    wait_for_signal(&backend.entered).await;
    let before = host.worker_health().ticks_completed;
    fixture.clock.set(expires_at.saturating_add(1));
    let observed = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        loop {
            let health = host.worker_health();
            if health.lifecycle == ResponseWorkerLifecycle::Failed
                || (health.ticks_completed > before && !fixture.has_active_overlay_contributions())
            {
                break health;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let health =
        observed.unwrap_or_else(|_| panic!("worker made no progress after delivery panic"));
    let readiness = host.ensure_ready();
    assert_eq!(
        health.lifecycle,
        ResponseWorkerLifecycle::Ready,
        "a backend panic must not kill the response worker: {health:?}"
    );
    assert!(health.ticks_completed > before);
    assert!(!fixture.has_active_overlay_contributions());
    let delivery = health
        .security_alert_delivery
        .unwrap_or_else(|| panic!("delivery health missing"));
    assert_eq!(
        delivery.last_error.as_deref(),
        Some("security alert delivery panicked")
    );
    assert!(
        matches!(readiness, Err(ProductionActiveDefenseHostError::SecurityAlertDelivery(ref message))
            if message == "security alert delivery panicked"),
        "the delivery panic must keep host readiness closed: {readiness:?}"
    );
    backend.panics.store(false, Ordering::Release);
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        loop {
            let recovered = host.worker_health();
            if recovered
                .security_alert_delivery
                .as_ref()
                .is_some_and(|current| {
                    current.passes > delivery.passes
                        && current.delivered == 1
                        && current.last_error.is_none()
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("a successful pass did not clear delivery health"));
    host.ensure_ready()
        .unwrap_or_else(|error| panic!("readiness after successful delivery: {error}"));
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown after backend panic: {error}"));
}

#[tokio::test]
async fn sqlite_delivery_wait_does_not_starve_containment_expiry() {
    let mut fixture = HostFixture::new();
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("alert tempdir: {error}"));
    let path = directory.path().join("contended-alerts.sqlite");
    let backend = Arc::new(ReleasedAlertBackend::default());
    install_alert_outbox(&mut fixture, &path, backend.clone(), 3);
    let expires_at = fixture.install_ttl_containment_plan();
    let now = fixture
        .clock
        .read_now_unix_ms()
        .unwrap_or_else(|error| panic!("fixture clock: {error}"));
    apply_escalation_plan(&fixture, now);
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    wait_for_signal(&backend.entered).await;
    // The backend is suspended after the outbox read, with no SQLite guard
    // held. Its confirmation will need a write transaction after release.
    let writer = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("contention connection: {error}"));
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap_or_else(|error| panic!("hold outbox writer: {error}"));
    backend.release.notify_one();
    wait_for_signal(&backend.returned).await;
    let before = host.worker_health().ticks_completed;
    fixture.clock.set(expires_at.saturating_add(1));
    let observed = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        loop {
            let health = host.worker_health();
            if health.ticks_completed > before && !fixture.has_active_overlay_contributions() {
                break health;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    writer
        .execute_batch("ROLLBACK")
        .unwrap_or_else(|error| panic!("release outbox writer: {error}"));
    let shutdown = host.shutdown().await;
    let health = observed.unwrap_or_else(|_| panic!("expiry stalled behind the outbox writer"));
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
    assert_eq!(
        health.security_alert_delivery.as_ref().map(|delivery| delivery.passes),
        Some(0),
        "expiry must progress during the blocked delivery pass, not after its SQLite timeout: {health:?}"
    );
    shutdown.unwrap_or_else(|error| panic!("shutdown after contention: {error}"));
}

#[tokio::test]
async fn dropping_the_host_mid_write_preserves_atomic_confirmation_and_recovery() {
    let mut fixture = HostFixture::new();
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("alert tempdir: {error}"));
    let path = directory.path().join("cancelled-alerts.sqlite");
    let backend = Arc::new(ReleasedAlertBackend::default());
    let outbox = install_alert_outbox(&mut fixture, &path, backend.clone(), 3);
    let row = page_escalation_alert(&fixture, &path);
    let due = u64::try_from(row.next_attempt_at_unix_ms)
        .unwrap_or_else(|error| panic!("due time: {error}"));
    fixture.clock.set(due.saturating_add(1));
    let host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    wait_for_signal(&backend.entered).await;
    let writer = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("contention connection: {error}"));
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap_or_else(|error| panic!("hold outbox writer: {error}"));
    backend.release.notify_one();
    wait_for_signal(&backend.returned).await;
    drop(host);
    writer
        .execute_batch("ROLLBACK")
        .unwrap_or_else(|error| panic!("release outbox writer: {error}"));
    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("host retained custody after the write finished"))
    .unwrap_or_else(|error| panic!("vacant registry: {error}"));
    let confirmed: Vec<(String, u32, Option<i64>)> = {
        let mut statement = writer.prepare(
            "SELECT status, attempts, delivered_at_unix_ms FROM chio_security_alert_outbox_backend"
        ).unwrap_or_else(|error| panic!("confirmation query: {error}"));
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap_or_else(|error| panic!("confirmations: {error}"))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|error| panic!("confirmation rows: {error}"))
    };
    assert!(
        confirmed.is_empty()
            || confirmed
                == vec![(
                    "delivered".to_owned(),
                    1,
                    Some(
                        i64::try_from(due.saturating_add(1))
                            .unwrap_or_else(|error| panic!("stored time: {error}"))
                    )
                )],
        "confirmation must be absent or committed atomically: {confirmed:?}"
    );
    backend.release.notify_one();
    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        outbox.deliver_due(due.saturating_add(1), 1),
    )
    .await
    .unwrap_or_else(|_| panic!("delivery did not recover after cancellation"))
    .unwrap_or_else(|error| panic!("delivery recovery: {error}"));
    let rows = outbox_rows(&path);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "delivered");
    assert_eq!(rows[0].attempts, 1);
}
