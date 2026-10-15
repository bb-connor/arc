use super::super::digest::{record_digest, RecordDigestInput};
use super::super::{verify_local_history, NativeIdentity, RecordKind};
use super::fixture::{assert_refused, Ledger, TestResult, SCOPE};

#[test]
fn workflow_native_identity_is_bound_into_the_record_digest() -> TestResult {
    let mut ledger = Ledger::new()?;
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: "request-1".to_owned(),
    };
    ledger.publish("workflow:w", RecordKind::Workflow, b"{}", Some(&native))?;
    verify_local_history(&ledger.connection)?;
    ledger.drop_guard("admission_operation_recovery_identity")?;
    ledger.connection.execute(
        "UPDATE admission_operation_recovery_records SET native_request = 'request-2'",
        [],
    )?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record digest differs from its event",
    );
    Ok(())
}

#[test]
fn payload_changed_outside_the_store_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    ledger.drop_guard("admission_operation_recovery_identity")?;
    ledger.connection.execute(
        "UPDATE admission_operation_recovery_records SET payload = ?1",
        [br#"{"v":9}"#.as_slice()],
    )?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record digest differs from its event",
    );
    Ok(())
}

#[test]
fn non_canonical_payload_refuses_even_with_a_matching_event() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish(
        "deployment:a",
        RecordKind::Deployment,
        br#"{"b":1,"a":2}"#,
        None,
    )?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record payload is not canonical JSON",
    );
    Ok(())
}

#[test]
fn non_canonical_scope_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let upper = SCOPE.to_ascii_uppercase();
    ledger.publish_in(&upper, "deployment:a", RecordKind::Deployment, b"{}", None)?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record identity is not canonical",
    );
    Ok(())
}

#[test]
fn current_version_without_its_event_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    ledger.write_record(
        SCOPE,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":2}"#,
        None,
    )?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record history coverage is incomplete",
    );
    Ok(())
}

#[test]
fn maximum_canonical_payload_verifies_at_its_known_digest() -> TestResult {
    let mut ledger = Ledger::new()?;
    let payload = format!("\"{}\"", "a".repeat(262_142));
    assert_eq!(payload.len(), 262_144);
    ledger.publish(
        "deployment:max",
        RecordKind::Deployment,
        payload.as_bytes(),
        None,
    )?;
    let digest = record_digest(&RecordDigestInput {
        key: "deployment:max",
        scope: SCOPE,
        kind: RecordKind::Deployment,
        version: 1,
        payload: payload.as_bytes(),
        native: None,
    })?;
    assert_eq!(
        digest,
        "0966d43ef0ced6d96773908745dbfd278949bb6ebc3cda90b6c28c1a10481f3d"
    );
    verify_local_history(&ledger.connection)?;
    Ok(())
}
