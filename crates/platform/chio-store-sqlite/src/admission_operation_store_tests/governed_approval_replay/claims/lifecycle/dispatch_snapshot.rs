use super::*;
use crate::admission_operation_store::governed_approval_claim as participant;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimDisposition;

#[test]
fn native_approval_ledger_snapshot_retains_exact_claim_after_release() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (initial, lease, credential) = setup(&fixture, "approval-ledger-snapshot")?;
    let intent = candidate(&initial, &authority, "claim", credential)?;
    let (operation, reference) =
        fixture
            .store
            .claim_governed_approval(&initial, &lease, &intent, now_ms())?;
    let snapshot = {
        let connection = fixture.store.connection()?;
        let snapshot =
            participant::dispatch_snapshot(&connection, &operation, 0)?.ok_or("live snapshot")?;
        assert_eq!(snapshot.reference, reference);
        assert_eq!(snapshot.intent, intent);
        assert_eq!(
            snapshot.disposition,
            GovernedApprovalClaimDisposition::ReservedBeforeDispatch
        );
        assert!(participant::dispatch_snapshot(&connection, &operation, 1).is_err());
        participant::verify_dispatch_snapshot(&connection, &operation, &Some(snapshot.clone()))?;
        let mut invalid = snapshot.clone();
        invalid.disposition = GovernedApprovalClaimDisposition::ReleasedBeforeDispatch;
        assert!(
            participant::verify_dispatch_snapshot(&connection, &operation, &Some(invalid)).is_err()
        );
        snapshot
    };
    let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
    fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())?;
    let connection = fixture.store.connection()?;
    assert!(participant::dispatch_snapshot(&connection, &operation, 0).is_err());
    participant::verify_dispatch_snapshot(&connection, &operation, &Some(snapshot))?;
    Ok(())
}
