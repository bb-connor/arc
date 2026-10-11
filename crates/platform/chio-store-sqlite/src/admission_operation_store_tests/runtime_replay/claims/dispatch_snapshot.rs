use super::*;
use crate::admission_operation_store::runtime_participant as participant;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantDisposition;

#[test]
fn native_runtime_ledger_snapshot_retains_exact_claim_after_release() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (initial, lease) = setup(&fixture, "runtime-ledger-snapshot")?;
    let intent = intent(&initial, &source, "claim", &[])?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&initial, &lease, &intent, now_ms())?;
    let snapshot = {
        let connection = fixture.store.connection()?;
        let snapshot =
            participant::dispatch_snapshot(&connection, &operation, 0)?.ok_or("live snapshot")?;
        assert_eq!(snapshot.reference, reference);
        assert_eq!(snapshot.intent, intent);
        assert_eq!(
            snapshot.disposition,
            RuntimeParticipantDisposition::ReservedBeforeDispatch
        );
        assert!(participant::dispatch_snapshot(&connection, &operation, 1).is_err());
        participant::verify_dispatch_snapshot(&connection, &operation, &Some(snapshot.clone()))?;
        let mut invalid = snapshot.clone();
        invalid.disposition = RuntimeParticipantDisposition::ReleasedBeforeDispatch;
        assert!(
            participant::verify_dispatch_snapshot(&connection, &operation, &Some(invalid)).is_err()
        );
        snapshot
    };
    let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    let connection = fixture.store.connection()?;
    assert!(participant::dispatch_snapshot(&connection, &operation, 0).is_err());
    participant::verify_dispatch_snapshot(&connection, &operation, &Some(snapshot))?;
    Ok(())
}
