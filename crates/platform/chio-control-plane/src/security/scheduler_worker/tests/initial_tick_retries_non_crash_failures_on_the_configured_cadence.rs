use super::*;


#[tokio::test]
async fn initial_tick_retries_non_crash_failures_on_the_configured_cadence() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
        Err(ResponseWorkerTickError::Port(PortError::unavailable())),
        Err(ResponseWorkerTickError::Port(PortError::unavailable())),
        Ok(tick("initial-retry-success")),
    ]));
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
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));

    let health = worker.health();
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
    assert_eq!(health.ticks_attempted, 3);
    assert_eq!(health.ticks_completed, 1);
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
}
