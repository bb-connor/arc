use super::*;
use crate::security::scheduler_worker::tests::*;

#[test]
fn reaper_spawn_failure_retains_join_ownership_for_later_recovery() {
    let registry = Arc::new(ResponseWorkerReaperRegistry::new());
    registry.fail_next_spawn.store(true, Ordering::Release);
    let permit = registry
        .acquire_without_service_for_test()
        .unwrap_or_else(|error| panic!("join permit: {error}"));
    let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let worker_for_thread = Arc::clone(&worker);
    let join = std::thread::spawn(move || worker_for_thread.complete_shutdown_after_loop());

    registry.enqueue(ResponseWorkerJoinJob {
        join,
        worker: Arc::clone(&worker),
        _permit: permit,
    });

    {
        let state = registry.lock_state();
        assert_eq!(state.jobs.len(), 1);
        assert_eq!(state.join_owners, 1);
        assert!(state.reaper.is_none());
    }
    let ResponseWorkerJoinJob {
        join,
        worker,
        _permit,
    } = registry
        .take_retained_job_for_test()
        .unwrap_or_else(|| panic!("retained join ownership was lost"));
    join_response_worker_thread(join, &worker)
        .unwrap_or_else(|error| panic!("retained join: {error}"));
    drop(_permit);
    assert_eq!(registry.lock_state().join_owners, 0);
    assert!(worker.thread_joined.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls(), 1);
}
