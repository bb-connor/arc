use super::*;

#[tokio::test]
async fn publication_remains_unready_until_the_first_tick_completes() {
    let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
        worker: Arc::clone(&worker),
    });
    let registry = ActiveDefenseServiceRegistry::default();
    registry
        .reserve_exact(Arc::clone(&services))
        .unwrap_or_else(|error| panic!("reserve: {error}"));
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
    assert!(registry.snapshot().is_none());
    assert!(!port.tick_started.load(Ordering::Acquire));

    registry
        .commit_reserved_exact_with_release(&services, || handle.release_publication())
        .unwrap_or_else(|error| panic!("publish: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("initial publication tick did not start"));

    assert!(registry.snapshot().is_some());
    assert!(!handle.is_running());
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Running);
    assert!(matches!(
        services.ensure_ready(),
        Err(ResponseWorkerTickError::WorkerPublicationPending)
    ));
    port.release();
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));
    assert!(handle.is_running());
    let health = worker.health();
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
    assert!(health.ticks_completed >= 1);
    services
        .ensure_ready()
        .unwrap_or_else(|error| panic!("published services are not ready: {error}"));
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    registry
        .unpublish_exact(&services)
        .unwrap_or_else(|error| panic!("unpublish: {error}"));
}
