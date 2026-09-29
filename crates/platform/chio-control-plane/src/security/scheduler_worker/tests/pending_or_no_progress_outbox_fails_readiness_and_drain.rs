use super::*;


#[test]
fn pending_or_no_progress_outbox_fails_readiness_and_drain() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        3,
        0,
        Vec::new(),
        vec![Ok(DeclassificationReceiptDrainReport {
            appended: 0,
            acknowledged: 0,
            deferred: 0,
            remaining: 3,
        })],
    ));
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    assert!(matches!(
        outbox.ensure_ready(),
        Err(ResponseWorkerTickError::DeclassificationOutboxPending(3))
    ));
    assert!(matches!(
        outbox.drain_one_batch(),
        Err(ResponseWorkerTickError::DeclassificationOutboxNoProgress(3))
    ));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed {
            pending_receipts: Some(3),
            ..
        }
    ));
}
