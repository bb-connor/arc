use super::*;


#[tokio::test]
async fn immediate_post_release_crash_keeps_the_degraded_services_published() {
    let failure = ResponseWorkerTickError::WorkerCrash(
        ErrorCode::new("response.post_release_crash")
            .unwrap_or_else(|error| panic!("error code: {error}")),
    );
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Err(failure)]));
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(port)
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

    registry
        .commit_reserved_exact_with_release(&services, || handle.release_publication())
        .unwrap_or_else(|error| panic!("publish: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while worker.health().lifecycle != ResponseWorkerLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("post-release worker crash was not observed"));

    assert!(registry.snapshot().is_some());
    assert!(services.ensure_ready().is_err());
    assert!(handle.shutdown().await.is_err());
    registry
        .unpublish_exact(&services)
        .unwrap_or_else(|error| panic!("unpublish failed services: {error}"));
}
