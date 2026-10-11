use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::IndexedSecurityEvidenceStore;
use chio_security_types::clock::FixedClock;
use chio_security_types::ports::TenantId;
use chio_store_sqlite::SqliteReceiptStore;

use super::{
    ProductionDeclassificationReceiptLifecycle, ProductionResponseWorker,
    ProductionResponseWorkerHandle, ProductionResponseWorkerLoopConfig,
    ProductionSecurityStateAuthority, ResponseWorkerPort, ResponseWorkerTick,
    ResponseWorkerTickError,
};

const CONTROL_LOCK_BOUND: Duration = Duration::from_millis(500);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Admission readiness probe that can be held open to stand in for slow
/// readiness I/O.
struct GatedReadinessPort {
    armed: AtomicBool,
    blocked: AtomicBool,
    released: AtomicBool,
}

impl GatedReadinessPort {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            blocked: AtomicBool::new(false),
            released: AtomicBool::new(false),
        }
    }

    fn arm(&self) {
        self.released.store(false, Ordering::Release);
        self.blocked.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }

    fn wait_until_blocked(&self) {
        let deadline = Instant::now() + PROBE_TIMEOUT;
        while !self.blocked.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "admission readiness probe never started"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl ResponseWorkerPort for GatedReadinessPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.blocked.store(true, Ordering::Release);
            while !self.released.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }

    fn tick(&self, _: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        Ok(ResponseWorkerTick {
            tenant_id: TenantId::new("tenant-runtime-lease")
                .unwrap_or_else(|error| panic!("tenant: {error}")),
            declassification_receipts_appended: 0,
            declassification_receipts_acknowledged: 0,
            declassification_receipts_pending: 0,
            declassification_receipts_compacted: 0,
            claimed: 0,
            completed_action_ids: Vec::new(),
            retry_action_ids: Vec::new(),
            lease_lost_action_ids: Vec::new(),
        })
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }
}

struct PublishedRuntime {
    _directory: tempfile::TempDir,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
    worker: Arc<ProductionResponseWorker>,
    handle: ProductionResponseWorkerHandle,
    port: Arc<GatedReadinessPort>,
}

async fn published_runtime() -> PublishedRuntime {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let clock = Arc::new(FixedClock::from_millis(50_000));
    let store_clock: Arc<dyn chio_store_sqlite::security_state::Clock> = clock.clone();
    let authority = ProductionSecurityStateAuthority::open_with_trusted_clock(
        directory.path().join("security-state.sqlite"),
        store_clock,
    )
    .unwrap_or_else(|error| panic!("security state authority: {error}"));
    let receipts: Arc<dyn IndexedSecurityEvidenceStore> = Arc::new(
        SqliteReceiptStore::open(directory.path().join("receipts.sqlite"))
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer: Arc<dyn SigningBackend> =
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[97_u8; 32])));
    let lifecycle =
        ProductionDeclassificationReceiptLifecycle::new(authority, receipts, signer, clock)
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
    lifecycle
        .reconcile_and_drain_startup()
        .unwrap_or_else(|error| panic!("reconcile startup: {error}"));
    let port = Arc::new(GatedReadinessPort::new());
    let worker = Arc::new(
        ProductionResponseWorker::new(port.clone())
            .unwrap_or_else(|error| panic!("response worker: {error}")),
    );
    lifecycle
        .bind_worker(&worker)
        .unwrap_or_else(|error| panic!("bind worker: {error}"));
    let mut handle = worker
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("start worker: {error}"));
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm worker: {error}"));
    lifecycle
        .publish_runtime_admission()
        .unwrap_or_else(|error| panic!("publish runtime admission: {error}"));
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("release publication: {error}"));
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));
    PublishedRuntime {
        _directory: directory,
        lifecycle,
        worker,
        handle,
        port,
    }
}

fn timed<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> mpsc::Receiver<(Duration, T)> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let result = work();
        let _ = sender.send((started.elapsed(), result));
    });
    receiver
}

#[tokio::test]
async fn consumer_readiness_probe_does_not_hold_the_runtime_control_lock_against_close() {
    let mut runtime = published_runtime().await;
    runtime.port.arm();
    let lifecycle = runtime.lifecycle.clone();
    let worker = Arc::clone(&runtime.worker);
    let acquisition = timed(move || {
        lifecycle
            .acquire_consumer_lease_for(&worker)
            .map(|_lease| ())
    });
    runtime.port.wait_until_blocked();

    let lifecycle = runtime.lifecycle.clone();
    let close = timed(move || lifecycle.close_runtime_admission());
    let close_during_probe = close.recv_timeout(CONTROL_LOCK_BOUND);
    let close_was_bounded = close_during_probe.is_ok();
    runtime.port.release();
    let (_, acquired) = acquisition
        .recv_timeout(PROBE_TIMEOUT)
        .unwrap_or_else(|_| panic!("consumer lease acquisition never finished"));
    let close_after_probe = match close_during_probe {
        Ok((_, result)) => result,
        Err(_) => {
            close
                .recv_timeout(PROBE_TIMEOUT)
                .unwrap_or_else(|_| panic!("close never finished"))
                .1
        }
    };
    let reclosed = runtime.lifecycle.close_runtime_admission();
    runtime
        .handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown worker: {error}"));

    assert!(
        close_was_bounded,
        "close_runtime_admission waited behind the consumer readiness probe for more than {CONTROL_LOCK_BOUND:?}"
    );
    assert!(
        matches!(
            close_after_probe,
            Err(ResponseWorkerTickError::ConsumerLeasesActive(1))
        ),
        "close during the probe must see the counted lease: {close_after_probe:?}"
    );
    assert!(
        matches!(
            acquired,
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        ),
        "a lease probed across close must not be granted: {acquired:?}"
    );
    assert!(
        matches!(reclosed, Ok(())),
        "the refused lease was not returned: {reclosed:?}"
    );
}

#[tokio::test]
async fn admission_readiness_probe_does_not_hold_the_runtime_control_lock_against_lease_drop() {
    let mut runtime = published_runtime().await;
    let held = runtime
        .lifecycle
        .acquire_consumer_lease_for(&runtime.worker)
        .unwrap_or_else(|error| panic!("first consumer lease: {error}"));
    runtime.port.arm();
    let lifecycle = runtime.lifecycle.clone();
    let probe = timed(move || lifecycle.ensure_runtime_admission_open());
    runtime.port.wait_until_blocked();

    let drop_lease = timed(move || drop(held));
    let drop_was_bounded = drop_lease.recv_timeout(CONTROL_LOCK_BOUND).is_ok();
    runtime.port.release();
    let (_, probed) = probe
        .recv_timeout(PROBE_TIMEOUT)
        .unwrap_or_else(|_| panic!("admission readiness probe never finished"));
    if !drop_was_bounded {
        drop_lease
            .recv_timeout(PROBE_TIMEOUT)
            .unwrap_or_else(|_| panic!("lease drop never finished"));
    }
    let closed = runtime.lifecycle.close_runtime_admission();
    runtime
        .handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown worker: {error}"));

    assert!(
        drop_was_bounded,
        "consumer lease drop waited behind the admission readiness probe for more than {CONTROL_LOCK_BOUND:?}"
    );
    assert!(
        matches!(probed, Ok(())),
        "published admission must stay open: {probed:?}"
    );
    assert!(
        matches!(closed, Ok(())),
        "the dropped lease was not returned: {closed:?}"
    );
}
