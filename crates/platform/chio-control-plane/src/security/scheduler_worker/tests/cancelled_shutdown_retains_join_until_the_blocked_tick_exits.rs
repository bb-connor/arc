use super::*;

#[tokio::test]
async fn cancelled_shutdown_retains_join_until_the_blocked_tick_exits() {
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

    assert!(
        tokio::time::timeout(Duration::from_millis(20), handle.shutdown())
            .await
            .is_err()
    );
    assert!(worker.shutdown_requested.load(Ordering::Acquire));
    assert!(handle.join.is_some());
    assert!(port.tick_in_flight.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
    assert!(!worker.shutdown_is_complete());

    let mut resumed_shutdown = Box::pin(handle.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut resumed_shutdown)
            .await
            .is_err()
    );
    assert!(port.tick_in_flight.load(Ordering::Acquire));
    assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
    assert!(!worker.shutdown_is_complete());
    assert!(tokio::time::timeout(
        Duration::from_millis(20),
        worker.wait_for_shutdown_completion(),
    )
    .await
    .is_err());

    port.release();
    resumed_shutdown
        .as_mut()
        .await
        .unwrap_or_else(|error| panic!("resumed shutdown: {error}"));
    drop(resumed_shutdown);

    assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
    assert!(worker.shutdown_is_complete());
    tokio::time::timeout(
        Duration::from_secs(1),
        worker.wait_for_shutdown_completion(),
    )
    .await
    .unwrap_or_else(|_| panic!("worker did not publish clean shutdown completion"));
    assert!(handle.clean_shutdown);
    assert!(handle.join.is_none());
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
}
