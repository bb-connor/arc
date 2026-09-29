use super::*;


#[test]
fn successful_cleanup_preserves_the_terminal_worker_failure() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
    let worker = ProductionResponseWorker::new_for_test(Arc::clone(&port))
        .unwrap_or_else(|error| panic!("worker: {error}"));
    let error = super::super::worker_task_crash_error();
    worker.mark_failed(&error);
    let failure = worker.health();
    worker.complete_shutdown_after_loop()
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Failed);
    assert_eq!(worker.health().last_error, failure.last_error);
    assert!(worker.shutdown_is_complete());
    assert_eq!(port.shutdown_calls(), 1);
}
