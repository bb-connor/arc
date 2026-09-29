use super::*;

#[test]
fn startup_reconciles_then_drains_to_zero_before_readiness() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        2,
        1,
        vec![Ok(DeclassificationReconciliationReport {
            reconciled: 1,
            remaining: 0,
        })],
        vec![
            Ok(DeclassificationReceiptDrainReport {
                appended: 1,
                acknowledged: 1,
                deferred: 0,
                remaining: 1,
            }),
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

    let report = outbox
        .reconcile_and_drain_startup()
        .unwrap_or_else(|error| panic!("startup drain: {error}"));

    assert_eq!(report.appended, 2);
    assert_eq!(report.acknowledged, 2);
    assert_eq!(report.remaining, 0);
    assert_eq!(
        scripted.events(),
        vec![
            "ensure",
            "count_stranded",
            "reconcile",
            "count_pending",
            "drain",
            "drain",
        ]
    );
    assert_eq!(outbox.health(), DeclassificationOutboxHealth::Ready);
}
