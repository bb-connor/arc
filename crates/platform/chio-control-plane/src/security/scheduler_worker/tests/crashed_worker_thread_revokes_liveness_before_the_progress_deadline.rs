use super::*;

#[tokio::test]
async fn crashed_worker_thread_revokes_liveness_before_the_progress_deadline() {
    let crash = ResponseWorkerTickError::WorkerCrash(
        ErrorCode::new("response.worker-thread-crash")
            .unwrap_or_else(|error| panic!("worker crash code: {error}")),
    );
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
        Ok(tick("initial-publication-readiness")),
        Err(crash),
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
        .unwrap_or_else(|error| panic!("release publication: {error}"));
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while worker.health().lifecycle != ResponseWorkerLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("worker thread did not report its crash"));

    assert!(!handle.is_running());
    assert!(matches!(
        worker.ensure_ready(),
        Err(ResponseWorkerTickError::WorkerStopped)
    ));
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Failed);

    assert!(handle.shutdown().await.is_err());
    assert_eq!(port.shutdown_calls(), 1);
}
