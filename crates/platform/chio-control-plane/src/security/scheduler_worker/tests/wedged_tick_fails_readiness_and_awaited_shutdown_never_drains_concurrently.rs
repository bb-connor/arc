use super::*;


#[tokio::test]
async fn wedged_tick_fails_readiness_and_awaited_shutdown_never_drains_concurrently() {
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
    worker.configure_progress(Duration::from_millis(30));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("tick did not start"));
    tokio::time::sleep(Duration::from_millis(40)).await;

    assert!(matches!(
        worker.ensure_ready(),
        Err(ResponseWorkerTickError::WorkerProgressStalled { .. })
    ));
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
    assert!(worker.health().tick_in_flight);

    port.release();
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
}
