use super::*;


#[test]
fn post_loop_cleanup_releases_owned_work_and_is_idempotent() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
    let worker = ProductionResponseWorker::new_for_test(Arc::clone(&port))
        .unwrap_or_else(|error| panic!("worker: {error}"));
    worker
        .complete_shutdown_after_loop()
        .unwrap_or_else(|error| panic!("first shutdown: {error}"));
    worker
        .complete_shutdown_after_loop()
        .unwrap_or_else(|error| panic!("second shutdown: {error}"));
    assert_eq!(port.shutdown_calls(), 1);
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
}
