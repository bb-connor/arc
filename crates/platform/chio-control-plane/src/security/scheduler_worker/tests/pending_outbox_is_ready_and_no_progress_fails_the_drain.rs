use super::*;

#[test]
fn pending_outbox_is_ready_and_no_progress_fails_the_drain() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        3,
        0,
        Vec::new(),
        vec![Ok(DeclassificationReceiptDrainReport {
            appended: 0,
            acknowledged: 0,
            deferred: 0,
            remaining: 3,
            remaining_due: 3,
        })],
    ));
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    outbox
        .ensure_ready()
        .unwrap_or_else(|error| panic!("pending receipts are not a readiness failure: {error}"));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Pending { receipts: 3 }
    ));
    assert!(matches!(
        outbox.drain_one_batch(),
        Err(ResponseWorkerTickError::DeclassificationOutboxNoProgress(3))
    ));
    outbox
        .ensure_ready()
        .unwrap_or_else(|error| panic!("readiness follows the tick, not the outbox: {error}"));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed {
            pending_receipts: Some(3),
            ..
        }
    ));
}
