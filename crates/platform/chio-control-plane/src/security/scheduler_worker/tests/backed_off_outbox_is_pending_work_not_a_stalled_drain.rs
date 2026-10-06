use super::*;

#[test]
fn backed_off_outbox_is_pending_work_not_a_stalled_drain() {
    let backed_off = || DeclassificationReceiptDrainReport {
        appended: 0,
        acknowledged: 0,
        deferred: 0,
        remaining: 3,
        remaining_due: 0,
    };
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        3,
        0,
        Vec::new(),
        vec![Ok(backed_off()), Ok(backed_off())],
    ));
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    assert!(matches!(
        outbox.drain_one_batch(),
        Ok(DeclassificationReceiptDrainReport { remaining: 3, .. })
    ));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Pending { receipts: 3 }
    ));
    assert!(matches!(
        outbox.drain_to_zero(),
        Ok(DeclassificationReceiptDrainReport { remaining: 3, .. })
    ));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Pending { receipts: 3 }
    ));
}
