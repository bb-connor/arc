use super::*;


#[test]
fn worker_crash_marks_health_failed_and_restart_can_take_over() {
    let failure = ResponseWorkerTickError::WorkerCrash(
        ErrorCode::new("response.worker_crash")
            .unwrap_or_else(|error| panic!("error code: {error}")),
    );
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
        Err(failure),
        Ok(tick("action-after-crash")),
    ]));
    let crashed = ProductionResponseWorker::new_for_test(Arc::clone(&port))
        .unwrap_or_else(|error| panic!("worker: {error}"));
    assert!(crashed.tick_once().is_err());
    assert_eq!(crashed.health().lifecycle, ResponseWorkerLifecycle::Failed);

    let restarted = ProductionResponseWorker::new_for_test(port)
        .unwrap_or_else(|error| panic!("restart: {error}"));
    assert_eq!(
        restarted
            .tick_once()
            .unwrap_or_else(|error| panic!("takeover: {error}"))
            .completed_action_ids
            .len(),
        1
    );
}
