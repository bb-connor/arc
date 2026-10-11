use super::*;

#[test]
fn periodic_compaction_failure_fails_maintenance_and_outbox_health() {
    let scripted = Arc::new(
        ScriptedDeclassificationOutboxPort::new(
            0,
            0,
            Vec::new(),
            vec![Ok(DeclassificationReceiptDrainReport::default())],
        )
        .with_compactions(vec![Err(PortError::unavailable())]),
    );
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted;
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    assert!(matches!(
        outbox.maintain_one_batch(),
        Err(ResponseWorkerTickError::DeclassificationOutbox(_))
    ));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed { .. }
    ));
}
