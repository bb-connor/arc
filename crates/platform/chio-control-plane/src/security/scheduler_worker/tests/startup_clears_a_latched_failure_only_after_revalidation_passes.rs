use super::*;
use chio_security_types::ports::{DeclassificationEvidencePhase, PortErrorKind};

fn failure_kind(error: &ResponseWorkerTickError) -> Option<PortErrorKind> {
    match error {
        ResponseWorkerTickError::DeclassificationOutbox(source) => Some(source.kind()),
        _ => None,
    }
}

#[test]
fn startup_clears_a_latched_failure_only_after_revalidation_passes() {
    let scripted = Arc::new(
        ScriptedDeclassificationOutboxPort::new(
            1,
            0,
            Vec::new(),
            vec![
                Err(PortError::integrity_failure()),
                Ok(DeclassificationReceiptDrainReport {
                    appended: 0,
                    acknowledged: 0,
                    deferred: 0,
                    remaining: 1,
                    remaining_due: 0,
                }),
            ],
        )
        .with_revalidations(vec![
            Err(PortError::unavailable()),
            Err(PortError::conflict()),
            Ok(DeclassificationRevalidationReport {
                revalidated: 1,
                last_tenant_id: Some(tenant()),
                last_grant_id: Some(
                    GrantId::new("grant-retried").unwrap_or_else(|error| panic!("grant: {error}")),
                ),
                last_phase: Some(DeclassificationEvidencePhase::Outcome),
            }),
        ]),
    );
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    let latched = outbox
        .drain_one_batch()
        .err()
        .unwrap_or_else(|| panic!("a fatal delivery failure drained"));
    assert_eq!(
        failure_kind(&latched),
        Some(PortErrorKind::IntegrityFailure)
    );

    // A transient revalidation failure fails startup and keeps the latch.
    let transient = outbox
        .reconcile_and_drain_startup()
        .err()
        .unwrap_or_else(|| panic!("startup passed an unavailable revalidation"));
    assert_eq!(failure_kind(&transient), Some(PortErrorKind::Unavailable));
    let closed = outbox
        .ensure_ready()
        .err()
        .unwrap_or_else(|| panic!("readiness reopened after an unavailable revalidation"));
    assert_eq!(failure_kind(&closed), Some(PortErrorKind::IntegrityFailure));

    // A mismatch found by revalidation fails startup with its own cause; the
    // first latched cause is kept.
    let mismatch = outbox
        .reconcile_and_drain_startup()
        .err()
        .unwrap_or_else(|| panic!("startup passed a revalidation mismatch"));
    assert_eq!(failure_kind(&mismatch), Some(PortErrorKind::Conflict));
    let closed = outbox
        .ensure_ready()
        .err()
        .unwrap_or_else(|| panic!("readiness reopened after a revalidation mismatch"));
    assert_eq!(failure_kind(&closed), Some(PortErrorKind::IntegrityFailure));

    // Revalidation passes: the latch clears and the backed-off receipt is
    // pending work.
    let report = outbox
        .reconcile_and_drain_startup()
        .unwrap_or_else(|error| panic!("startup after revalidation: {error}"));
    assert_eq!((report.remaining, report.remaining_due), (1, 0));
    outbox
        .ensure_ready()
        .unwrap_or_else(|error| panic!("readiness after revalidation: {error}"));
    assert_eq!(
        outbox.health(),
        DeclassificationOutboxHealth::Pending { receipts: 1 }
    );
    assert_eq!(
        scripted.events(),
        vec![
            "drain",
            "count_pending",
            "ensure",
            "revalidate",
            "count_pending",
            "count_pending",
            "ensure",
            "revalidate",
            "count_pending",
            "count_pending",
            "ensure",
            "revalidate",
            "count_stranded",
            "count_pending",
            "drain",
            "count_pending",
        ]
    );
}
