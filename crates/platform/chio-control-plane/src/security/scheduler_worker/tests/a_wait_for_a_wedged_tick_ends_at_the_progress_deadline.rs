use std::time::Instant;

use super::*;

#[tokio::test]
async fn a_wait_for_a_wedged_tick_ends_at_the_progress_deadline() {
    let port = Arc::new(BlockingWorkerPort::new());
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let config = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_millis(10),
    };
    let mut handle = worker
        .start_parked(config)
        .await
        .unwrap_or_else(|error| panic!("parked start: {error}"));
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
    tokio::time::timeout(Duration::from_secs(5), async {
        while !port.tick_started.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the blocking tick did not start"));
    let wedged = worker
        .health()
        .last_tick_started_sequence
        .unwrap_or_else(|| panic!("the wedged tick has no sequence"));

    let started = Instant::now();
    let stalled = tokio::time::timeout(
        Duration::from_secs(30),
        worker.wait_for_tick_completion(wedged, config),
    )
    .await;
    let waited = started.elapsed();
    port.release();
    let completed = tokio::time::timeout(
        Duration::from_secs(5),
        worker.wait_for_tick_completion(wedged, config),
    )
    .await;
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));

    match stalled {
        Ok(Err(ResponseWorkerTickError::WorkerProgressStalled {
            started_sequence,
            completed_sequence,
        })) => {
            assert_eq!(started_sequence, Some(wedged));
            assert!(completed_sequence < Some(wedged));
        }
        Ok(other) => panic!("the wait must report the stalled tick: {other:?}"),
        Err(_) => panic!("the wait on a wedged tick ignored the progress deadline"),
    }
    assert!(
        waited >= config.progress_deadline(),
        "the wait gave up after {waited:?}, before the progress deadline"
    );
    assert!(
        matches!(completed, Ok(Ok(()))),
        "the released tick was not observed as complete: {completed:?}"
    );
}
