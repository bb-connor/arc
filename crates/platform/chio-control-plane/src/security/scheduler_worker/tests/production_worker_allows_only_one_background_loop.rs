use super::*;


#[tokio::test]
async fn production_worker_allows_only_one_background_loop() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(tick(
        "initial-publication-readiness",
    ))]));
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let config = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_secs(30),
    };
    let mut handle = worker
        .start_parked(config)
        .await
        .unwrap_or_else(|error| panic!("first start: {error}"));

    assert!(matches!(
        worker.start_parked(config).await,
        Err(ResponseWorkerTickError::WorkerAlreadyRunning)
    ));

    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("release publication: {error}"));
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));

    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    assert_eq!(port.shutdown_calls(), 1);
}
