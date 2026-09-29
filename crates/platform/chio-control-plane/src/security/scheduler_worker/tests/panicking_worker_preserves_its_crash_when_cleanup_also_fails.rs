use super::*;

#[test]
fn panicking_worker_preserves_its_crash_when_cleanup_also_fails() {
    struct CrashThenCleanupFailure;
    impl ResponseWorkerPort for CrashThenCleanupFailure {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            Ok(())
        }

        fn tick(&self, _: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
            panic!("controlled worker panic before cleanup");
        }

        fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
            Err(ResponseWorkerTickError::Port(PortError::unavailable()))
        }
    }
    let worker = ProductionResponseWorker::new_for_test(Arc::new(CrashThenCleanupFailure))
        .unwrap_or_else(|error| panic!("worker: {error}"));
    assert!(matches!(
        worker.tick_once_catching_crash(),
        Err(ResponseWorkerTickError::WorkerCrash(_))
    ));
    let crash = worker.health();
    assert_eq!(crash.lifecycle, ResponseWorkerLifecycle::Failed);
    assert!(worker.complete_shutdown_after_loop().is_err());
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Failed);
    assert_eq!(worker.health().last_error, crash.last_error);
    assert!(!worker.shutdown_is_complete());
}
