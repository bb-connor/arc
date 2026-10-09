use super::*;
use crate::security::scheduler_worker::tests::*;

fn queued_worker(
    registry: &Arc<ResponseWorkerReaperRegistry>,
    parked: Option<std::sync::mpsc::Receiver<()>>,
) -> (Arc<ProductionResponseWorker>, Arc<ScriptedWorkerPort>) {
    let permit = registry
        .acquire()
        .unwrap_or_else(|error| panic!("join permit: {error}"));
    let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let worker_for_thread = Arc::clone(&worker);
    let registry_for_thread = Arc::clone(registry);
    let join = std::thread::spawn(move || {
        if let Some(parked) = parked {
            let _ = parked.recv();
        }
        let result = worker_for_thread.complete_shutdown_after_loop();
        registry_for_thread.note_thread_exit(std::thread::current().id());
        result
    });
    permit.transfer(join, Arc::clone(&worker));
    (worker, port)
}

fn wait_for_join_owners(registry: &ResponseWorkerReaperRegistry, expected: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while registry.lock_state().join_owners != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "join owners did not reach {expected}"
        );
        std::thread::yield_now();
    }
}

#[test]
fn a_parked_worker_does_not_hold_back_the_reaping_of_a_finished_one() {
    let registry = Arc::new(ResponseWorkerReaperRegistry::new());
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let (wedged, wedged_port) = queued_worker(&registry, Some(parked));
    let (finished, finished_port) = queued_worker(&registry, None);

    wait_for_join_owners(&registry, 1);
    assert!(finished.thread_joined.load(Ordering::Acquire));
    assert_eq!(finished_port.shutdown_calls(), 1);
    assert!(!wedged.thread_joined.load(Ordering::Acquire));
    assert_eq!(wedged_port.shutdown_calls(), 0);
    assert_eq!(registry.lock_state().jobs.len(), 1);

    release
        .send(())
        .unwrap_or_else(|error| panic!("release wedged worker: {error}"));
    wait_for_join_owners(&registry, 0);
    assert!(wedged.thread_joined.load(Ordering::Acquire));
    assert_eq!(wedged_port.shutdown_calls(), 1);
    assert!(registry.lock_state().exited.is_empty());
}
