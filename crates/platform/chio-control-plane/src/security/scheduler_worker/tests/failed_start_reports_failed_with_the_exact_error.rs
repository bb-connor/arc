use super::*;

#[tokio::test]
async fn failed_start_reports_failed_with_the_exact_error() {
    let crash = ErrorCode::new("response.test_initial_tick_crash")
        .unwrap_or_else(|error| panic!("error code: {error}"));
    let expected = ResponseWorkerTickError::WorkerCrash(crash.clone()).to_string();
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Err(
        ResponseWorkerTickError::WorkerCrash(crash),
    )]));
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
    let mut phase = handle.phase.subscribe();
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("publication: {error}"));

    match handle.wait_for_publication_readiness().await {
        Err(ResponseWorkerTickError::WorkerInitialTick(message)) => {
            assert_eq!(message, expected);
        }
        other => panic!("expected the initial tick failure, got {other:?}"),
    }
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Failed(expected));
    assert!(!handle.is_running());
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Failed);
    assert!(!worker.publication_ready.load(Ordering::Acquire));
    assert!(matches!(
        handle.shutdown().await,
        Err(ResponseWorkerTickError::WorkerCrash(_))
    ));
    assert_eq!(
        *phase.borrow(),
        WorkerPhase::Failed(
            ResponseWorkerTickError::WorkerCrash(
                ErrorCode::new("response.test_initial_tick_crash")
                    .unwrap_or_else(|error| panic!("error code: {error}"))
            )
            .to_string()
        ),
        "a recorded failure is final"
    );
}
