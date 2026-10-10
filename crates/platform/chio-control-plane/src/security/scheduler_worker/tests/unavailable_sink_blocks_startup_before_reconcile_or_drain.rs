use super::*;

#[test]
fn unavailable_sink_blocks_startup_before_reconcile_or_drain() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        1,
        1,
        Vec::new(),
        Vec::new(),
    ));
    scripted.set_available(false);
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    assert!(matches!(
        outbox.reconcile_and_drain_startup(),
        Err(ResponseWorkerTickError::DeclassificationOutbox(_))
    ));
    assert_eq!(scripted.events(), vec!["ensure", "count_pending"]);
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed { .. }
    ));
}
