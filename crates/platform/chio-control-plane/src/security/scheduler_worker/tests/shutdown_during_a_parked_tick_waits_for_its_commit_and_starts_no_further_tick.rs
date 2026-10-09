use super::*;

/// A port whose second tick parks until released and then commits.
struct CommitAfterParkPort {
    tick_calls: AtomicU64,
    parked: AtomicBool,
    release: AtomicBool,
    committed: AtomicBool,
    committed_at_shutdown: AtomicBool,
    shutdown_calls: AtomicU64,
}

impl ResponseWorkerPort for CommitAfterParkPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn tick(&self, sequence: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        self.tick_calls.fetch_add(1, Ordering::AcqRel);
        if sequence == 1 {
            self.parked.store(true, Ordering::Release);
            while !self.release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            self.committed.store(true, Ordering::Release);
        }
        Ok(tick("commit-after-park"))
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        self.committed_at_shutdown
            .store(self.committed.load(Ordering::Acquire), Ordering::Release);
        self.shutdown_calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[tokio::test]
async fn shutdown_during_a_parked_tick_waits_for_its_commit_and_starts_no_further_tick() {
    let port = Arc::new(CommitAfterParkPort {
        tick_calls: AtomicU64::new(0),
        parked: AtomicBool::new(false),
        release: AtomicBool::new(false),
        committed: AtomicBool::new(false),
        committed_at_shutdown: AtomicBool::new(false),
        shutdown_calls: AtomicU64::new(0),
    });
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
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
        while !port.parked.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("tick did not park"));

    let mut shutdown = Box::pin(handle.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
            .await
            .is_err()
    );
    assert!(!port.committed.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);

    port.release.store(true, Ordering::Release);
    let released_at = tokio::time::Instant::now();
    shutdown
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    assert!(
        released_at.elapsed() < Duration::from_secs(2),
        "shutdown must return promptly once the parked tick ends"
    );
    assert!(port.committed.load(Ordering::Acquire));
    assert!(
        port.committed_at_shutdown.load(Ordering::Acquire),
        "the port shut down only after the tick committed"
    );
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        port.tick_calls.load(Ordering::Acquire),
        2,
        "no tick starts after the stop request"
    );
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
}
