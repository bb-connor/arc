use super::*;

#[tokio::test]
async fn dropping_the_handle_publishes_stopping_and_the_reaper_joins_the_worker() {
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
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("tick did not start"));
    let mut phase = handle.phase.subscribe();
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Ready);

    drop(handle);
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Stopping);
    assert!(!worker.thread_joined.load(Ordering::Acquire));

    port.release();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !worker.thread_joined.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the reaper did not join the dropped worker"));
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Stopped);
    assert!(worker.shutdown_is_complete());
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
}
