use super::*;


#[tokio::test]
async fn cancelled_publication_wait_transfers_join_ownership_without_blocking_drop() {
    let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let mut handle = worker
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30),
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
    tokio::time::timeout(Duration::from_secs(1), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("initial publication tick did not start"));

    let startup = async move {
        handle.wait_for_publication_readiness().await?;
        Ok::<ProductionResponseWorkerHandle, ResponseWorkerTickError>(handle)
    };
    assert!(tokio::time::timeout(Duration::from_millis(20), startup)
        .await
        .is_err());
    assert!(worker.shutdown_requested.load(Ordering::Acquire));
    assert!(!worker.thread_joined.load(Ordering::Acquire));

    port.release();
    tokio::time::timeout(
        Duration::from_secs(1),
        worker.wait_for_shutdown_completion(),
    )
    .await
    .unwrap_or_else(|_| panic!("cancelled startup worker did not stop"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !worker.thread_joined.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("cancelled startup worker thread was not joined"));
    assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
}
