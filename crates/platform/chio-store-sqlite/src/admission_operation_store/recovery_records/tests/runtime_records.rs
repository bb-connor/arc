use serde::{Deserialize, Serialize};

use super::super::{load_record, NativeIdentity, RecordKind};
use super::fixture::{assert_refused, Ledger, TestResult, SCOPE};

#[derive(Debug, Deserialize, Serialize)]
struct Narrow {
    a: u64,
}

#[test]
fn current_record_is_bound_to_its_latest_event() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    let second = ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":2}"#, None)?;
    let record = load_record(&ledger.connection, "deployment:a")?.ok_or("record is absent")?;
    assert_eq!(record.version, 2);
    assert_eq!(record.kind, RecordKind::Deployment);
    assert_eq!(record.scope, SCOPE);
    assert_eq!(record.payload, br#"{"v":2}"#);
    assert_eq!(record.native, None);
    assert_eq!(record.event.sequence, ledger.sequence());
    assert_eq!(record.event.record_version, 2);
    assert_eq!(record.event.event_digest, second.event_digest);
    let value: serde_json::Value = record.decode_payload()?;
    assert_eq!(value, serde_json::json!({ "v": 2 }));
    Ok(())
}

#[test]
fn absent_record_in_an_empty_initialized_catalog_is_pristine() -> TestResult {
    let ledger = Ledger::new()?;
    ledger.install_global_commits()?;
    assert_eq!(load_record(&ledger.connection, "workflow:absent")?, None);
    Ok(())
}

#[test]
fn runtime_absence_requires_the_global_commit_catalog() -> TestResult {
    let ledger = Ledger::new()?;
    assert_refused(
        load_record(&ledger.connection, "workflow:absent"),
        "recovery global commit catalog is absent",
    );
    Ok(())
}

#[test]
fn absent_record_with_only_a_retained_global_commit_refuses() -> TestResult {
    let ledger = Ledger::new()?;
    ledger.install_global_commits()?;
    ledger.commit(1, "command:gone", 1, &"e".repeat(64))?;
    assert_refused(
        load_record(&ledger.connection, "command:gone"),
        "recovery record disappeared with retained history",
    );
    Ok(())
}

#[test]
fn absent_record_with_retained_history_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.install_global_commits()?;
    ledger.publish("command:c", RecordKind::Command, b"{}", None)?;
    ledger.drop_guard("admission_operation_recovery_records_no_delete")?;
    ledger.connection.execute(
        "DELETE FROM admission_operation_recovery_records WHERE record_key = 'command:c'",
        [],
    )?;
    assert_refused(
        load_record(&ledger.connection, "command:c"),
        "recovery record disappeared with retained history",
    );
    Ok(())
}

#[test]
fn record_keys_outside_the_catalog_bound_refuse_before_any_read() -> TestResult {
    let ledger = Ledger::new()?;
    for key in [String::new(), "k".repeat(513)] {
        assert_refused(
            load_record(&ledger.connection, &key),
            "recovery record key exceeds its bound",
        );
    }
    Ok(())
}

#[test]
fn typed_decode_refuses_bytes_the_type_would_not_reproduce() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("command:c", RecordKind::Command, br#"{"a":1,"b":2}"#, None)?;
    let record = load_record(&ledger.connection, "command:c")?.ok_or("record is absent")?;
    assert_refused(
        record.decode_payload::<Narrow>(),
        "recovery record payload is not exact canonical data",
    );
    Ok(())
}

#[test]
fn runtime_workflow_returns_its_authenticated_native_identity() -> TestResult {
    let mut ledger = Ledger::new()?;
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: "request-1".to_owned(),
    };
    ledger.publish(
        "workflow:native",
        RecordKind::Workflow,
        b"{}",
        Some(&native),
    )?;
    let record = load_record(&ledger.connection, "workflow:native")?.ok_or("record is absent")?;
    assert_eq!(record.kind, RecordKind::Workflow);
    assert_eq!(record.native, Some(native));
    Ok(())
}

#[test]
fn runtime_record_returns_the_complete_maximum_canonical_payload() -> TestResult {
    let mut ledger = Ledger::new()?;
    let payload = format!("\"{}\"", "a".repeat(262_142));
    assert_eq!(payload.len(), 262_144);
    ledger.publish(
        "deployment:max",
        RecordKind::Deployment,
        payload.as_bytes(),
        None,
    )?;
    let record = load_record(&ledger.connection, "deployment:max")?.ok_or("record is absent")?;
    assert_eq!(record.payload, payload.as_bytes());
    assert_eq!(
        record.event.record_digest,
        "0966d43ef0ced6d96773908745dbfd278949bb6ebc3cda90b6c28c1a10481f3d"
    );
    Ok(())
}
