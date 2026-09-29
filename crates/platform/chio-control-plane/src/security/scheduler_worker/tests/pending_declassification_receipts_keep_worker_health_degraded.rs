use super::*;


#[test]
fn pending_declassification_receipts_keep_worker_health_degraded() {
    let mut pending = tick("action-with-pending-evidence");
    pending.declassification_receipts_pending = 3;
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(pending)]));
    let worker = ProductionResponseWorker::new_for_test(port)
        .unwrap_or_else(|error| panic!("worker: {error}"));

    worker
        .tick_once()
        .unwrap_or_else(|error| panic!("pending evidence tick: {error}"));

    let health = worker.health();
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Degraded);
    assert_eq!(
        health.last_error.as_deref(),
        Some("3 declassification receipts remain pending")
    );
}
