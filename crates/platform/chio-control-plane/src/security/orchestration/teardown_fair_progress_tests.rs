use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chio_core::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::IndexedSecurityEvidenceStore;
use chio_security_types::clock::FixedClock;
use chio_security_types::ports::PortError;
use chio_store_sqlite::SqliteReceiptStore;

use super::{
    ActiveDefenseTeardownRetry, ActiveDefenseTeardownSupervisor, ReservedActiveDefenseCleanup,
    RetainedActiveDefenseCleanupWork,
};
use crate::security::orchestration::{
    ProductionDeclassificationReceiptLifecycle, ProductionSecurityStateAuthority,
};
use crate::security::{
    ActiveDefenseServiceRegistry, ActiveDefenseServices, ProductionResponseWorker,
    ProductionResponseWorkerLoopConfig, ResponseWorkerHealth, ResponseWorkerPort,
    ResponseWorkerTick, ResponseWorkerTickError,
};

const PROGRESS_TIMEOUT: Duration = Duration::from_secs(10);
const INDEPENDENT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(5);
const PARKED_RETRY_INTERVAL: Duration = Duration::from_millis(1_500);

struct ShutdownGatePort {
    released: AtomicBool,
    shutdown_attempts: AtomicU64,
    attempt_times: Mutex<Vec<Instant>>,
}

impl ShutdownGatePort {
    fn new(released: bool) -> Self {
        Self {
            released: AtomicBool::new(released),
            shutdown_attempts: AtomicU64::new(0),
            attempt_times: Mutex::new(Vec::new()),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }

    fn shutdown_attempts(&self) -> u64 {
        self.shutdown_attempts.load(Ordering::Acquire)
    }

    fn attempt_gaps(&self) -> Vec<Duration> {
        let times = self
            .attempt_times
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        times
            .windows(2)
            .map(|pair| pair[1].saturating_duration_since(pair[0]))
            .collect()
    }
}

impl ResponseWorkerPort for ShutdownGatePort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn tick(&self, _: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        Err(ResponseWorkerTickError::Port(PortError::unavailable()))
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        self.attempt_times
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Instant::now());
        self.shutdown_attempts.fetch_add(1, Ordering::AcqRel);
        if self.released.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(ResponseWorkerTickError::Port(PortError::unavailable()))
        }
    }
}

struct ReservedServices;

impl ActiveDefenseServices for ReservedServices {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn worker_health(&self) -> ResponseWorkerHealth {
        ResponseWorkerHealth::created()
    }
}

struct ReservedCleanupFixture {
    _directory: tempfile::TempDir,
    registry: Arc<ActiveDefenseServiceRegistry>,
    port: Arc<ShutdownGatePort>,
    cleanup: ReservedActiveDefenseCleanup,
}

async fn reserved_cleanup(shutdown_released: bool, start_worker: bool) -> ReservedCleanupFixture {
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
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[93_u8; 32])));
    let lifecycle =
        ProductionDeclassificationReceiptLifecycle::new(authority, receipts, signer, clock.clone())
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
    let registry = Arc::new(ActiveDefenseServiceRegistry::default());
    let services: Arc<dyn ActiveDefenseServices> = Arc::new(ReservedServices);
    registry
        .reserve_exact(Arc::clone(&services))
        .unwrap_or_else(|error| panic!("reserve services: {error}"));
    let port = Arc::new(ShutdownGatePort::new(shutdown_released));
    let active_worker = Arc::new(
        ProductionResponseWorker::new(port.clone())
            .unwrap_or_else(|error| panic!("response worker: {error}")),
    );
    let worker_handle = if start_worker {
        Some(
            active_worker
                .start_parked(ProductionResponseWorkerLoopConfig {
                    tick_interval: Duration::from_millis(10),
                })
                .await
                .unwrap_or_else(|error| panic!("start parked worker: {error}")),
        )
    } else {
        None
    };
    ReservedCleanupFixture {
        _directory: directory,
        registry: Arc::clone(&registry),
        port,
        cleanup: ReservedActiveDefenseCleanup {
            registry,
            lifecycle,
            published_services: services,
            worker_handle,
            active_worker,
            reservation_active: true,
        },
    }
}

async fn released(registry: &ActiveDefenseServiceRegistry, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, registry.wait_until_vacant())
        .await
        .is_ok_and(|vacancy| vacancy.is_ok())
}

async fn wait_for(description: &str, mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(PROGRESS_TIMEOUT, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{description}"));
}

#[tokio::test]
async fn never_ending_reserved_cleanup_does_not_block_an_independent_queued_cleanup() {
    let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
    let ReservedCleanupFixture {
        _directory: _stuck_directory,
        registry: stuck_registry,
        port: stuck_port,
        cleanup: stuck_cleanup,
    } = reserved_cleanup(false, true).await;
    let ReservedCleanupFixture {
        _directory: _independent_directory,
        registry: independent_registry,
        port: _independent_port,
        cleanup: independent_cleanup,
    } = reserved_cleanup(true, false).await;

    supervisor
        .acquire()
        .unwrap_or_else(|error| panic!("acquire stuck cleanup permit: {error}"))
        .enqueue(RetainedActiveDefenseCleanupWork::Reserved(stuck_cleanup));
    wait_for(
        "stuck cleanup never entered its worker shutdown retry",
        || stuck_port.shutdown_attempts() >= 2,
    )
    .await;
    supervisor
        .acquire()
        .unwrap_or_else(|error| panic!("acquire independent cleanup permit: {error}"))
        .enqueue(RetainedActiveDefenseCleanupWork::Reserved(
            independent_cleanup,
        ));

    let independent_completed = released(&independent_registry, INDEPENDENT_PROGRESS_TIMEOUT).await;
    let attempts_while_independent_ran = stuck_port.shutdown_attempts();
    let stuck_reservation_held = !released(&stuck_registry, Duration::from_millis(200)).await;
    let retained_while_stuck = supervisor.lock_state().retained_owners;
    let stuck_kept_retrying = tokio::time::timeout(INDEPENDENT_PROGRESS_TIMEOUT, async {
        while stuck_port.shutdown_attempts() <= attempts_while_independent_ran {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    stuck_port.release();
    let stuck_completed = released(&stuck_registry, PROGRESS_TIMEOUT).await;
    wait_for("teardown permits were not returned", || {
        supervisor.lock_state().retained_owners == 0
    })
    .await;

    assert!(
        independent_completed,
        "a never-ending cleanup blocked an independent queued cleanup: stuck shutdown attempts={attempts_while_independent_ran} retained owners={retained_while_stuck}"
    );
    assert!(stuck_reservation_held);
    assert_eq!(retained_while_stuck, 1);
    assert!(stuck_kept_retrying);
    assert!(stuck_completed);
}

#[tokio::test]
async fn parked_cleanup_keeps_its_reservation_and_retries_at_the_parked_interval() {
    let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
    let ReservedCleanupFixture {
        _directory: _parked_directory,
        registry,
        port,
        cleanup,
    } = reserved_cleanup(false, true).await;
    supervisor
        .acquire()
        .unwrap_or_else(|error| panic!("acquire parked cleanup permit: {error}"))
        .enqueue_with_retry_for_test(
            RetainedActiveDefenseCleanupWork::Reserved(cleanup),
            ActiveDefenseTeardownRetry::bounded_for_test(3, PARKED_RETRY_INTERVAL),
        );

    wait_for("parked cleanup stopped retrying", || {
        port.shutdown_attempts() >= 5
    })
    .await;
    let gaps = port.attempt_gaps();
    let reservation_held = !released(&registry, Duration::from_millis(200)).await;
    let retained_while_parked = supervisor.lock_state().retained_owners;
    port.release();
    let completed = released(&registry, PROGRESS_TIMEOUT).await;
    wait_for("teardown permit was not returned", || {
        supervisor.lock_state().retained_owners == 0
    })
    .await;

    assert!(
        gaps.len() >= 4 && gaps[..2].iter().all(|gap| *gap < PARKED_RETRY_INTERVAL),
        "bounded attempts were not at the retry interval: {gaps:?}"
    );
    assert!(
        gaps[2..4].iter().all(|gap| *gap >= PARKED_RETRY_INTERVAL),
        "cleanup was not parked after its bounded attempts: {gaps:?}"
    );
    assert!(reservation_held);
    assert_eq!(retained_while_parked, 1);
    assert!(completed);
}
