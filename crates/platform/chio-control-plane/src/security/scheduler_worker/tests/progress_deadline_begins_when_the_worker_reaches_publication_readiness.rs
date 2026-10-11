use super::*;

#[test]
fn progress_deadline_begins_when_the_worker_reaches_publication_readiness() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
    let worker = ProductionResponseWorker::new_for_test(port)
        .unwrap_or_else(|error| panic!("worker: {error}"));
    worker.configure_progress(Duration::from_millis(1));
    worker.task_live.store(true, Ordering::Release);
    worker
        .mark_publication_released()
        .unwrap_or_else(|error| panic!("release publication: {error}"));

    std::thread::sleep(Duration::from_millis(20));
    worker
        .ensure_ready()
        .unwrap_or_else(|error| panic!("unobserved publication stalled: {error}"));

    worker
        .mark_publication_ready()
        .unwrap_or_else(|error| panic!("mark publication ready: {error}"));
    std::thread::sleep(Duration::from_millis(20));
    assert!(matches!(
        worker.ensure_ready(),
        Err(ResponseWorkerTickError::WorkerProgressStalled { .. })
    ));
}
