use super::*;


#[tokio::test]
async fn parked_worker_commit_failure_stops_with_zero_ticks() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(tick(
        "action-must-not-run",
    ))]));
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
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("parked start: {error}"));
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    tokio::task::yield_now().await;
    assert_eq!(port.tick_calls(), 0);
    assert!(registry.snapshot().is_none());

    port.set_ready(false);
    let release_called = AtomicBool::new(false);
    assert!(registry
        .commit_reserved_exact_with_release(&services, || {
            release_called.store(true, Ordering::Release);
            handle.release_publication()
        })
        .is_err());
    assert!(!release_called.load(Ordering::Acquire));
    assert!(registry.snapshot().is_none());
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("parked shutdown: {error}"));
    assert_eq!(port.tick_calls(), 0);
    assert_eq!(port.shutdown_calls(), 1);
    registry
        .cancel_reserved_exact(&services)
        .unwrap_or_else(|error| panic!("cancel reserve: {error}"));
}
