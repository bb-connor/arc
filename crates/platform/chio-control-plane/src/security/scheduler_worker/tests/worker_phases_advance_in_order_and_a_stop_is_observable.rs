use super::*;

async fn phase_after(
    receiver: &mut tokio::sync::watch::Receiver<WorkerPhase>,
    expected: WorkerPhase,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if *receiver.borrow_and_update() == expected {
                return;
            }
            receiver
                .changed()
                .await
                .unwrap_or_else(|error| panic!("phase channel closed: {error}"));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("phase {expected:?} was not reached"));
}

#[tokio::test]
async fn worker_phases_advance_in_order_and_a_stop_is_observable() {
    let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
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
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Created);

    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Armed);

    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("publication: {error}"));
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::PublicationReleased);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("initial tick did not start"));
    assert_eq!(
        *phase.borrow(),
        WorkerPhase::PublicationReleased,
        "readiness is only reported after the initial tick completes"
    );

    port.release();
    phase_after(&mut phase, WorkerPhase::Ready).await;
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("readiness: {error}"));

    port.release_tick.store(false, Ordering::Release);
    port.tick_started.store(false, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("periodic tick did not start"));

    let mut shutdown = Box::pin(handle.shutdown());
    let _elapsed = tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
        .await
        .unwrap_err();
    assert_eq!(*phase.borrow_and_update(), WorkerPhase::Stopping);

    port.release();
    shutdown
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    phase_after(&mut phase, WorkerPhase::Stopped).await;
}
