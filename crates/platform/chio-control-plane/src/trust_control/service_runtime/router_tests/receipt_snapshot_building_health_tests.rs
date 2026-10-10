//! Public health remains available while the real snapshot walker is building.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use chio_store_sqlite::receipt_query_snapshot::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use std::sync::{Condvar, Weak};

const HANG: Duration = Duration::from_secs(60);

struct PauseState {
    observer: Option<Weak<ReceiptQuerySnapshots>>,
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    released: bool,
}

/// The worker first waits for its observer to be installed. It then pauses on
/// the existing clock port only when the read-only phase sample is Building.
struct BuildingClock {
    fixed: FixedClock,
    pause: Mutex<PauseState>,
    changed: Condvar,
}

impl BuildingClock {
    fn new(entered: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            fixed: FixedClock::new(1_760_000_000_000),
            pause: Mutex::new(PauseState {
                observer: None,
                entered: Some(entered),
                released: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn observe(&self, snapshots: &Arc<ReceiptQuerySnapshots>) -> Result<(), ClockError> {
        self.pause
            .lock()
            .map_err(|_| ClockError::Unavailable)?
            .observer = Some(Arc::downgrade(snapshots));
        self.changed.notify_all();
        Ok(())
    }

    fn release(&self) {
        self.pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .released = true;
        self.changed.notify_all();
    }
}

impl Clock for BuildingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if std::thread::current().name() != Some("chio-receipt-query-snapshot") {
            return self.fixed.read();
        }
        let observer = {
            let pause = self.pause.lock().map_err(|_| ClockError::Unavailable)?;
            let (pause, _) = self
                .changed
                .wait_timeout_while(pause, HANG, |pause| {
                    pause.observer.is_none() && !pause.released
                })
                .map_err(|_| ClockError::Unavailable)?;
            if pause.released {
                return self.fixed.read();
            }
            pause.observer.clone().ok_or(ClockError::Unavailable)?
        };
        // Release the observer mutex before sampling the service's phase.
        let snapshots = observer.upgrade().ok_or(ClockError::Unavailable)?;
        if matches!(
            snapshots.health_status().state,
            ReceiptQuerySnapshotState::Building { .. }
        ) {
            let mut pause = self.pause.lock().map_err(|_| ClockError::Unavailable)?;
            if let Some(entered) = pause.entered.take() {
                entered.send(()).map_err(|_| ClockError::Unavailable)?;
            }
            let (pause, _) = self
                .changed
                .wait_timeout_while(pause, HANG, |pause| !pause.released)
                .map_err(|_| ClockError::Unavailable)?;
            if !pause.released {
                return Err(ClockError::Unavailable);
            }
        }
        self.fixed.read()
    }
}

/// Even a failed assertion releases the clock before joining the walker.
struct WalkerPause {
    clock: Arc<BuildingClock>,
    snapshots: Arc<ReceiptQuerySnapshots>,
}

impl Drop for WalkerPause {
    fn drop(&mut self) {
        self.clock.release();
        self.snapshots.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_building_snapshot_health_ignores_exhausted_receipt_admission() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let clock = Arc::new(BuildingClock::new(entered));
    let store = Arc::new(SqliteReceiptStore::open_with_clock(&path, clock.clone())?);
    store.wait_for_writer_ready(HANG)?;
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    let _pause = WalkerPause {
        clock: Arc::clone(&clock),
        snapshots: Arc::clone(&snapshots),
    };
    clock.observe(&snapshots)?;
    tokio::time::timeout(Duration::from_secs(30), entered_rx).await??;
    assert!(matches!(
        snapshots.health_status().state,
        ReceiptQuerySnapshotState::Building { .. }
    ));

    let mut state = metrics_state("snapshot-secret");
    state.config.receipt_db_path = Some(path);
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    let _held = Arc::clone(&state.receipt_query_lane).try_acquire_many_owned(4)?;
    assert_eq!(state.receipt_query_lane.available_permits(), 0);
    let request = Request::builder().uri("/health").body(Body::empty())?;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        super::super::super::build_router(state.clone()).oneshot(request),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        body["receiptQuerySnapshot"],
        json!({"configured": true, "state": "building"}),
        "public health must not disclose counts, watermarks or diagnostics while building"
    );
    assert_eq!(state.receipt_query_lane.available_permits(), 0);
    assert!(matches!(
        snapshots.health_status().state,
        ReceiptQuerySnapshotState::Building { .. }
    ));

    clock.release();
    let ready = tokio::task::spawn_blocking(move || {
        snapshots.wait_for_recovery(Duration::from_secs(30), |status| {
            status.state == ReceiptQuerySnapshotState::Ready
        })
    })
    .await?;
    assert_eq!(ready.state, ReceiptQuerySnapshotState::Ready);
    Ok(())
}
