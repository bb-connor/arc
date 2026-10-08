use std::time::Instant;

use super::*;

const CLEANUP_PASSES: u64 = 20;
const UNENDING_CLEANUP_PASSES: usize = 10_000;

async fn published(
    port: &Arc<ScriptedWorkerPort>,
    config: ProductionResponseWorkerLoopConfig,
) -> (
    Arc<ProductionResponseWorker>,
    ProductionResponseWorkerHandle,
    Result<(), ResponseWorkerTickError>,
    Duration,
) {
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let mut handle = worker
        .start_parked(config)
        .await
        .unwrap_or_else(|error| panic!("start: {error}"));
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    let released_at = Instant::now();
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("publication: {error}"));
    let readiness = handle.wait_for_publication_readiness().await;
    (worker, handle, readiness, released_at.elapsed())
}

#[tokio::test]
async fn initial_terminal_cleanup_continuations_are_paced_within_the_deadline() {
    let mut ticks: Vec<_> = (0..CLEANUP_PASSES)
        .map(|_| Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending))
        .collect();
    ticks.push(Ok(tick("initial-cleanup-drained")));
    let port = Arc::new(ScriptedWorkerPort::with_ticks(ticks));
    let config = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_millis(50),
    };

    let (worker, mut handle, readiness, elapsed) = published(&port, config).await;
    let health = worker.health();
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));

    readiness.unwrap_or_else(|error| panic!("a draining backlog must reach readiness: {error}"));
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
    assert_eq!(health.ticks_attempted, CLEANUP_PASSES + 1);
    let paced = config
        .poll_interval()
        .saturating_mul(u32::try_from(CLEANUP_PASSES).unwrap_or(u32::MAX));
    assert!(
        elapsed >= paced,
        "{CLEANUP_PASSES} cleanup continuations finished in {elapsed:?}, faster than {paced:?}"
    );
}

#[tokio::test]
async fn an_unending_initial_cleanup_backlog_fails_at_the_deadline_without_spinning() {
    let ticks = (0..UNENDING_CLEANUP_PASSES)
        .map(|_| Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending))
        .collect();
    let port = Arc::new(ScriptedWorkerPort::with_ticks(ticks));
    let config = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_millis(10),
    };

    let (_worker, mut handle, readiness, _) = published(&port, config).await;
    let _ = handle.shutdown().await;

    match readiness {
        Err(ResponseWorkerTickError::WorkerInitialTick(message)) => assert_eq!(
            message,
            ResponseWorkerTickError::TerminalSchedulerCleanupPending.to_string()
        ),
        other => panic!("the backlog must fail initial readiness at the deadline: {other:?}"),
    }
    let polls = config.progress_deadline().as_millis() / config.poll_interval().as_millis();
    let bound = u64::try_from(polls.saturating_mul(2)).unwrap_or(u64::MAX);
    assert!(
        port.tick_calls() <= bound,
        "{} cleanup passes ran within the {:?} deadline; at most {bound} are paced",
        port.tick_calls(),
        config.progress_deadline()
    );
}
