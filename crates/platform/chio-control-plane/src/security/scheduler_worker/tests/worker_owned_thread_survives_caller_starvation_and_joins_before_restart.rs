use super::*;

#[tokio::test(flavor = "current_thread")]
async fn worker_owned_thread_survives_caller_starvation_and_joins_before_restart() {
    let ticks = (0..64)
        .map(|_| Ok(tick("worker-owned-thread-progress")))
        .collect();
    let port = Arc::new(ScriptedWorkerPort::with_ticks(ticks));

    for generation in 0..2 {
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker {generation}: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start worker {generation}: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm worker {generation}: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publish worker {generation}: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| {
                panic!("publication readiness for worker {generation}: {error}")
            });
        let completed_before_starvation = worker.health().ticks_completed;

        std::thread::sleep(Duration::from_millis(100));

        let completed_after_starvation = worker.health().ticks_completed;
        assert!(completed_after_starvation > completed_before_starvation);
        worker
            .ensure_ready()
            .unwrap_or_else(|error| panic!("worker {generation} stalled: {error}"));
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown worker {generation}: {error}"));
        assert!(!worker.task_live.load(Ordering::Acquire));
        assert!(worker.shutdown_is_complete());
        assert!(handle.join.is_none());
    }

    assert_eq!(port.shutdown_calls(), 2);
}
