use super::*;

#[test]
fn periodic_drain_failure_can_recover_on_a_later_batch() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        1,
        0,
        Vec::new(),
        vec![
            Err(PortError::unavailable()),
            Ok(DeclassificationReceiptDrainReport {
                appended: 1,
                acknowledged: 1,
                deferred: 0,
                remaining: 0,
            }),
        ],
    ));
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    assert!(outbox.drain_one_batch().is_err());
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed { .. }
    ));
    let recovered = outbox
        .drain_one_batch()
        .unwrap_or_else(|error| panic!("recovery drain: {error}"));
    assert_eq!(recovered.acknowledged, 1);
    assert_eq!(outbox.health(), DeclassificationOutboxHealth::Ready);
    assert_eq!(
        scripted.requested_batches(),
        vec![
            MAX_DECLASSIFICATION_EVIDENCE_BATCH,
            MAX_DECLASSIFICATION_EVIDENCE_BATCH,
        ]
    );
}
