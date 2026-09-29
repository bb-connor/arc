use super::*;

#[test]
fn production_worker_restart_recovers_after_ack_loss_without_duplicate_completion() {
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
        Err(ResponseWorkerTickError::AckLost),
        Ok(tick("action-recovered")),
    ]));
    let first = ProductionResponseWorker::new_for_test(Arc::clone(&port))
        .unwrap_or_else(|error| panic!("first worker: {error}"));
    assert!(matches!(
        first.tick_once(),
        Err(ResponseWorkerTickError::AckLost)
    ));

    let restarted = ProductionResponseWorker::new_for_test(Arc::clone(&port))
        .unwrap_or_else(|error| panic!("restarted worker: {error}"));
    let recovered = restarted
        .tick_once()
        .unwrap_or_else(|error| panic!("recovery tick: {error}"));
    assert_eq!(recovered.completed_action_ids.len(), 1);
    assert_eq!(
        recovered.completed_action_ids[0].as_str(),
        "action-recovered"
    );
}
