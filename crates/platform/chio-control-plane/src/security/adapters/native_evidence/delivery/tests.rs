use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

use chio_security_types::ports::{
    AlertDeliveryQuery, AlertDeliveryStatus, Digest32, RecordId, SecurityAlert, SecurityAlertPort,
    TenantId,
};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteSecurityAlertOutboxStore;
use futures_util::FutureExt;

use super::*;
use crate::security::adapters::AlertOutboxConfig;

const NOW: u64 = 1_700_000_000_000;

#[derive(Default)]
struct ConfirmingBackend(AtomicUsize);

impl AlertBackend for ConfirmingBackend {
    fn name(&self) -> &str {
        "delivery-store-test"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

fn alert() -> SecurityAlert {
    let record = |text| RecordId::new(text).unwrap_or_else(|error| panic!("record: {error}"));
    SecurityAlert {
        tenant_id: TenantId::new("delivery-store-test")
            .unwrap_or_else(|error| panic!("tenant: {error}")),
        event_id: record("delivery-store-event"),
        idempotency_key: record("delivery-store-key"),
        occurred_at_unix_ms: NOW - 1_000,
        alert_type: record("response_rollback_partial"),
        finding_id_hash: Digest32::new([1; 32]),
        action_id_hash: Some(Digest32::new([2; 32])),
        evidence_hash: Digest32::new([3; 32]),
    }
}

fn fixture() -> (
    tempfile::TempDir,
    Arc<SecurityAlertOutbox>,
    Arc<ConfirmingBackend>,
) {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityAlertOutboxStore::open(directory.path().join("alerts.sqlite"))
        .unwrap_or_else(|error| panic!("store: {error}"));
    let backend = Arc::new(ConfirmingBackend::default());
    let outbox = Arc::new(
        SecurityAlertOutbox::new(
            Arc::new(store),
            vec![backend.clone()],
            AlertOutboxConfig::default(),
        )
        .unwrap_or_else(|error| panic!("outbox: {error}")),
    );
    outbox
        .page(&alert())
        .unwrap_or_else(|error| panic!("page: {error}"));
    (directory, outbox, backend)
}

fn status(outbox: &SecurityAlertOutbox) -> Option<AlertDeliveryStatus> {
    SecurityAlertPort::load_delivery(outbox, &AlertDeliveryQuery { alert: alert() })
        .unwrap_or_else(|error| panic!("status: {error}"))
}

#[tokio::test]
async fn a_store_panic_propagates_without_blocking_the_next_delivery_pass() {
    let (_directory, outbox, backend) = fixture();
    let guard = Arc::clone(&outbox.delivery_lock).lock_owned().await;
    let failure = AssertUnwindSafe(outbox.with_store::<(), _>(guard, |store| {
        store.ensure_ready()?;
        panic!("injected delivery store panic");
    }))
    .catch_unwind()
    .await;
    let Err(payload) = failure else {
        panic!("the injected store panic was not propagated");
    };
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"injected delivery store panic")
    );
    let report = outbox
        .deliver_due(NOW, 1)
        .await
        .unwrap_or_else(|error| panic!("recovery: {error}"));
    assert_eq!(report.delivered, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(backend.0.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn cancellation_retains_delivery_custody_until_the_write_finishes() {
    let (_directory, outbox, _) = fixture();
    let guard = Arc::clone(&outbox.delivery_lock).lock_owned().await;
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let writer = Arc::clone(&outbox);
    let task = tokio::spawn(async move {
        writer
            .with_store(guard, move |store| {
                let row = store
                    .load_due(NOW, 1)?
                    .pop()
                    .ok_or_else(PortError::unavailable)?;
                entered.send(()).map_err(|_| PortError::unavailable())?;
                released.recv().map_err(|_| PortError::unavailable())?;
                store.record_failure(&row, NOW + 1)
            })
            .await
    });
    waiting
        .await
        .unwrap_or_else(|error| panic!("write entry: {error}"));
    task.abort();
    let Err(cancelled) = task.await else {
        panic!("the waiting delivery task completed before write release");
    };
    assert!(cancelled.is_cancelled());
    match outbox.delivery_lock.try_lock() {
        Err(_) => {}
        Ok(_) => panic!("cancellation released delivery custody during a write"),
    }
    release
        .send(())
        .unwrap_or_else(|error| panic!("release write: {error}"));
    let _guard = Arc::clone(&outbox.delivery_lock).lock_owned().await;
    assert_eq!(
        status(&outbox),
        Some(AlertDeliveryStatus::Pending {
            attempts: 1,
            next_attempt_at_unix_ms: NOW + 1,
        })
    );
}
