use super::*;

#[tokio::test]
async fn published_worker_with_failing_ticks_is_not_ready() {
    let failing = || Err(ResponseWorkerTickError::Port(PortError::unavailable()));
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
        Ok(tick("initial-publication-readiness")),
        failing(),
        failing(),
        failing(),
    ]));
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
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let health = worker.health();
            if health.ticks_attempted >= 3 && !health.tick_in_flight {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("failing ticks were not observed"));

    assert!(services.ensure_ready().is_err());
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    registry
        .unpublish_exact(&services)
        .unwrap_or_else(|error| panic!("unpublish: {error}"));
}
