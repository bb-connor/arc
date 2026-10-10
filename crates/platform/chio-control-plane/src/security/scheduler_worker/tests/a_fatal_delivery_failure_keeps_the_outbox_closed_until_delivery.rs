use super::*;
use chio_security_types::ports::PortErrorKind;

fn backed_off(remaining: u64) -> DeclassificationReceiptDrainReport {
    DeclassificationReceiptDrainReport {
        appended: 0,
        acknowledged: 0,
        deferred: 0,
        remaining,
        remaining_due: 0,
    }
}

fn is_integrity_failure(error: &ResponseWorkerTickError) -> bool {
    matches!(
        error,
        ResponseWorkerTickError::DeclassificationOutbox(source)
            if source.kind() == PortErrorKind::IntegrityFailure
    )
}

#[test]
fn a_fatal_delivery_failure_keeps_the_outbox_closed_until_delivery() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        1,
        0,
        Vec::new(),
        vec![
            Err(PortError::integrity_failure()),
            Ok(backed_off(1)),
            Ok(backed_off(1)),
            Ok(DeclassificationReceiptDrainReport {
                appended: 1,
                acknowledged: 1,
                deferred: 0,
                remaining: 0,
                remaining_due: 0,
            }),
        ],
    ));
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    match outbox.drain_one_batch() {
        Err(error) => assert!(is_integrity_failure(&error), "{error}"),
        Ok(report) => panic!("a fatal delivery failure drained: {report:?}"),
    }
    // The failed receipt is now in retry backoff, so nothing is due. The
    // outbox stays failed with the original cause until it is delivered.
    match outbox.drain_one_batch() {
        Err(error) => assert!(is_integrity_failure(&error), "{error}"),
        Ok(report) => panic!("a zero-due tick reopened a fatal failure: {report:?}"),
    }
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed { .. }
    ));
    match outbox.ensure_ready() {
        Err(error) => assert!(is_integrity_failure(&error), "{error}"),
        Ok(()) => panic!("readiness reopened after a fatal delivery failure"),
    }
    match outbox.drain_to_zero() {
        Err(error) => assert!(is_integrity_failure(&error), "{error}"),
        Ok(report) => panic!("a zero-due drain reopened a fatal failure: {report:?}"),
    }

    scripted.pending.store(0, Ordering::SeqCst);
    let delivered = outbox
        .drain_one_batch()
        .unwrap_or_else(|error| panic!("delivery after backoff: {error}"));
    assert_eq!(delivered.acknowledged, 1);
    assert_eq!(outbox.health(), DeclassificationOutboxHealth::Ready);
    outbox
        .ensure_ready()
        .unwrap_or_else(|error| panic!("readiness after delivery: {error}"));
}

#[test]
fn a_transient_delivery_failure_backs_off_as_pending_work() {
    let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
        1,
        0,
        Vec::new(),
        vec![Err(PortError::unavailable()), Ok(backed_off(1))],
    ));
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    assert!(matches!(outbox.drain_one_batch(),
        Err(ResponseWorkerTickError::DeclassificationOutbox(source))
            if source.kind() == PortErrorKind::Unavailable));
    let backed_off = outbox
        .drain_one_batch()
        .unwrap_or_else(|error| panic!("transient backoff: {error}"));
    assert_eq!(backed_off.remaining, 1);
    assert_eq!(
        outbox.health(),
        DeclassificationOutboxHealth::Pending { receipts: 1 }
    );
    outbox
        .ensure_ready()
        .unwrap_or_else(|error| panic!("readiness during transient backoff: {error}"));
}
