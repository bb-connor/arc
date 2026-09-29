use super::*;


#[tokio::test]
async fn dropping_handle_signals_stop_without_concurrent_drain_or_zombie_tick() {
    let port = Arc::new(BlockingWorkerPort::new());
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let mut handle = worker
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("parked start: {error}"));
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
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("tick did not start"));

    drop(handle);
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
    port.release();
    tokio::time::timeout(
        Duration::from_secs(1),
        worker.wait_for_shutdown_completion(),
    )
    .await
    .unwrap_or_else(|_| panic!("worker did not stop"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !worker.thread_joined.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("dropped worker thread was not joined"));
    assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
}
