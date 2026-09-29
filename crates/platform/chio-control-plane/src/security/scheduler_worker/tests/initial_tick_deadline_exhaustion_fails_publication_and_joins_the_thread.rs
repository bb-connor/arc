use super::*;


#[tokio::test]
async fn initial_tick_deadline_exhaustion_fails_publication_and_joins_the_thread() {
    let failures = (0..8)
        .map(|_| Err(ResponseWorkerTickError::Port(PortError::unavailable())))
        .collect();
    let port = Arc::new(ScriptedWorkerPort::with_ticks(failures));
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

    assert!(matches!(
        handle.wait_for_publication_readiness().await,
        Err(ResponseWorkerTickError::WorkerInitialTick(_))
    ));
    assert!(handle.shutdown().await.is_err());
    assert!(!worker.task_live.load(Ordering::Acquire));
    assert!(handle.join.is_none());
}
