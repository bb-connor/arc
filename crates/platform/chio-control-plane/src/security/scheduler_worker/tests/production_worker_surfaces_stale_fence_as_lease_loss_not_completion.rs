use super::*;

#[test]
fn production_worker_surfaces_stale_fence_as_lease_loss_not_completion() {
    let stale = ResponseWorkerTick {
        tenant_id: tenant(),
        declassification_receipts_appended: 0,
        declassification_receipts_acknowledged: 0,
        declassification_receipts_pending: 0,
        declassification_receipts_compacted: 0,
        claimed: 1,
        completed_action_ids: Vec::new(),
        retry_action_ids: Vec::new(),
        lease_lost_action_ids: vec![
            ActionId::new("action-stale").unwrap_or_else(|error| panic!("action id: {error}"))
        ],
    };
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(stale)]));
    let worker = ProductionResponseWorker::new_for_test(port)
        .unwrap_or_else(|error| panic!("worker: {error}"));
    let report = worker
        .tick_once()
        .unwrap_or_else(|error| panic!("stale tick: {error}"));
    assert!(report.completed_action_ids.is_empty());
    assert_eq!(report.lease_lost_action_ids.len(), 1);
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
}
