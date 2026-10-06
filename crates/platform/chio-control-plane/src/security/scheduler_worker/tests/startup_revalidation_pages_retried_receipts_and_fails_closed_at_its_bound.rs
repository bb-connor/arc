use super::super::outbox::MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES;
use super::*;
use chio_security_types::ports::{DeclassificationEvidencePhase, PortErrorKind};

fn page(revalidated: u32, grant: &str) -> DeclassificationRevalidationReport {
    DeclassificationRevalidationReport {
        revalidated,
        last_tenant_id: Some(tenant()),
        last_grant_id: Some(GrantId::new(grant).unwrap_or_else(|error| panic!("grant: {error}"))),
        last_phase: Some(DeclassificationEvidencePhase::Outcome),
    }
}

fn after(report: &DeclassificationRevalidationReport) -> DeclassificationRetriedEvidenceQuery {
    DeclassificationRetriedEvidenceQuery {
        after_tenant_id: report.last_tenant_id.clone(),
        after_grant_id: report.last_grant_id.clone(),
        after_phase: report.last_phase,
        max_records: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
    }
}

fn first_page() -> DeclassificationRetriedEvidenceQuery {
    DeclassificationRetriedEvidenceQuery {
        after_tenant_id: None,
        after_grant_id: None,
        after_phase: None,
        max_records: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
    }
}

#[test]
fn startup_revalidation_pages_retried_receipts_and_fails_closed_at_its_bound() {
    let full_one = page(MAX_DECLASSIFICATION_EVIDENCE_BATCH, "grant-page-one");
    let full_two = page(MAX_DECLASSIFICATION_EVIDENCE_BATCH, "grant-page-two");
    let paged = Arc::new(
        ScriptedDeclassificationOutboxPort::new(0, 0, Vec::new(), Vec::new()).with_revalidations(
            vec![
                Ok(full_one.clone()),
                Ok(full_two.clone()),
                Ok(page(3, "grant-page-three")),
            ],
        ),
    );
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = paged.clone();
    ProductionDeclassificationReceiptOutbox::new_for_test(port)
        .reconcile_and_drain_startup()
        .unwrap_or_else(|error| panic!("paged startup: {error}"));
    assert_eq!(
        paged.requested_revalidations(),
        vec![first_page(), after(&full_one), after(&full_two)]
    );

    let pass_bound = usize::try_from(MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES)
        .unwrap_or_else(|error| panic!("pass bound: {error}"));
    let unbounded = Arc::new(
        ScriptedDeclassificationOutboxPort::new(1, 1, Vec::new(), Vec::new()).with_revalidations(
            (0..=pass_bound)
                .map(|index| {
                    Ok(page(
                        MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                        &format!("g-{index}"),
                    ))
                })
                .collect(),
        ),
    );
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = unbounded.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);
    match outbox.reconcile_and_drain_startup() {
        Err(ResponseWorkerTickError::DeclassificationRevalidationLimit(revalidated)) => {
            assert_eq!(
                revalidated,
                u64::from(MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES)
                    * u64::from(MAX_DECLASSIFICATION_EVIDENCE_BATCH)
            );
        }
        other => panic!("revalidation past its bound: {other:?}"),
    }
    assert_eq!(unbounded.requested_revalidations().len(), pass_bound);
    assert!(!unbounded
        .events()
        .iter()
        .any(|event| matches!(*event, "count_stranded" | "reconcile" | "drain")));
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed { .. }
    ));

    let malformed = Arc::new(
        ScriptedDeclassificationOutboxPort::new(1, 0, Vec::new(), Vec::new()).with_revalidations(
            vec![Ok(DeclassificationRevalidationReport {
                revalidated: 1,
                ..DeclassificationRevalidationReport::default()
            })],
        ),
    );
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = malformed.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);
    for result in [
        outbox.reconcile_and_drain_startup().map(|_| ()),
        outbox.ensure_ready(),
    ] {
        assert!(matches!(
            result,
            Err(ResponseWorkerTickError::DeclassificationOutbox(source))
                if source.kind() == PortErrorKind::IntegrityFailure
        ));
    }
}
