use super::*;
use crate::security::scheduler_worker::tests::*;

#[test]
fn reaper_blocks_on_the_worker_join_without_polling() {
    let registry = Arc::new(ResponseWorkerReaperRegistry::new());
    let permit = registry
        .acquire()
        .unwrap_or_else(|error| panic!("join permit: {error}"));
    let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let worker_for_thread = Arc::clone(&worker);
    let join = std::thread::spawn(move || {
        let _ = parked.recv();
        worker_for_thread.complete_shutdown_after_loop()
    });

    permit.transfer(join, Arc::clone(&worker));
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        registry.idle_wakeups.load(Ordering::Acquire) <= 2,
        "a reaper waiting on a running worker must not wake on a timer"
    );
    assert!(!worker.thread_joined.load(Ordering::Acquire));
    assert_eq!(registry.lock_state().join_owners, 1);

    release
        .send(())
        .unwrap_or_else(|error| panic!("release worker thread: {error}"));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while registry.lock_state().join_owners != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the reaper did not join the worker thread"
        );
        std::thread::yield_now();
    }
    assert!(worker.thread_joined.load(Ordering::Acquire));
    assert_eq!(port.shutdown_calls(), 1);
    assert!(registry.idle_wakeups.load(Ordering::Acquire) <= 3);
}
