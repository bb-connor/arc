use rusqlite::Connection;

use crate::serving_owner::SqliteServingOwnerError;

use super::super::{projection_reference, verify_local_history, RecordKind};
use super::fixture::{assert_refused, EventSeed, Ledger, TestResult};

fn three_events(ledger: &mut Ledger) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(vec![
        ledger
            .publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?
            .event_digest,
        ledger
            .publish("command:c", RecordKind::Command, br#"{"c":1}"#, None)?
            .event_digest,
        ledger
            .publish("deployment:a", RecordKind::Deployment, br#"{"v":2}"#, None)?
            .event_digest,
    ])
}

#[test]
fn local_history_verifies_before_the_global_catalog_exists() -> TestResult {
    let mut ledger = Ledger::new()?;
    let digests = three_events(&mut ledger)?;
    verify_local_history(&ledger.connection)?;
    assert_eq!(
        projection_reference(&ledger.connection, "deployment:a", 1)?,
        digests[0]
    );
    assert_eq!(
        projection_reference(&ledger.connection, "deployment:a", 2)?,
        digests[2]
    );
    assert_eq!(
        projection_reference(&ledger.connection, "command:c", 1)?,
        digests[1]
    );
    Ok(())
}

#[test]
fn missing_record_catalog_refuses() -> TestResult {
    let connection = Connection::open_in_memory()?;
    assert_refused(
        verify_local_history(&connection),
        "recovery record catalog is absent",
    );
    Ok(())
}

#[test]
fn event_whose_digest_does_not_match_its_fields_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    ledger.write_record(
        super::fixture::SCOPE,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":2}"#,
        None,
    )?;
    let digest = ledger.current_digest("deployment:a", RecordKind::Deployment, br#"{"v":2}"#)?;
    let head = ledger.head().to_owned();
    ledger.append_event_with_digest(
        &EventSeed {
            sequence: 2,
            key: "deployment:a",
            version: 2,
            record_digest: &digest,
            previous: &head,
            observed: 2,
        },
        &"f".repeat(64),
    )?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history event is corrupt",
    );
    Ok(())
}

/// Appends version 2 of `deployment:a` at the given chain position.
fn append_second(
    ledger: &mut Ledger,
    sequence: u64,
    previous: &str,
    observed: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    ledger.write_record(
        super::fixture::SCOPE,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":2}"#,
        None,
    )?;
    let digest = ledger.current_digest("deployment:a", RecordKind::Deployment, br#"{"v":2}"#)?;
    ledger.append_event(&EventSeed {
        sequence,
        key: "deployment:a",
        version: 2,
        record_digest: &digest,
        previous,
        observed,
    })?;
    Ok(())
}

#[test]
fn sequence_gap_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    let head = ledger.head().to_owned();
    let skipped = ledger.sequence() + 2;
    append_second(&mut ledger, skipped, &head, 2)?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history sequence has a gap",
    );
    Ok(())
}

#[test]
fn broken_previous_link_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    append_second(&mut ledger, 2, &"0".repeat(64), 2)?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history link is broken",
    );
    Ok(())
}

#[test]
fn observed_time_regression_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let scope = super::fixture::SCOPE;
    ledger.write_record(
        scope,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":1}"#,
        None,
    )?;
    let digest = ledger.current_digest("deployment:a", RecordKind::Deployment, br#"{"v":1}"#)?;
    let genesis = "0".repeat(64);
    let first = ledger.append_event(&EventSeed {
        sequence: 1,
        key: "deployment:a",
        version: 1,
        record_digest: &digest,
        previous: &genesis,
        observed: 5,
    })?;
    append_second(&mut ledger, 2, &first.event_digest, 4)?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history time regressed",
    );
    Ok(())
}

#[test]
fn skipped_record_version_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    let scope = super::fixture::SCOPE;
    ledger.write_record(
        scope,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":2}"#,
        None,
    )?;
    ledger.write_record(
        scope,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":3}"#,
        None,
    )?;
    let digest = ledger.current_digest("deployment:a", RecordKind::Deployment, br#"{"v":3}"#)?;
    let head = ledger.head().to_owned();
    ledger.append_event(&EventSeed {
        sequence: 2,
        key: "deployment:a",
        version: 3,
        record_digest: &digest,
        previous: &head,
        observed: 2,
    })?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record version is not contiguous",
    );
    Ok(())
}

#[test]
fn current_record_ahead_of_its_history_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    ledger.write_record(
        super::fixture::SCOPE,
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
fn history_of_a_deleted_record_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("command:c", RecordKind::Command, b"{}", None)?;
    ledger.drop_guard("admission_operation_recovery_records_no_delete")?;
    ledger
        .connection
        .execute("DELETE FROM admission_operation_recovery_records", [])?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history names an absent record",
    );
    Ok(())
}

#[test]
fn projection_reference_refuses_absent_events_and_owners() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("command:c", RecordKind::Command, b"{}", None)?;
    for (key, version, expected) in [
        (
            "command:c",
            2,
            "recovery record projection reference is absent",
        ),
        (
            "command:absent",
            1,
            "recovery record projection reference is absent",
        ),
    ] {
        match projection_reference(&ledger.connection, key, version) {
            Err(SqliteServingOwnerError::Invalid(detail)) => assert_eq!(detail, expected),
            other => panic!("expected refusal {expected:?}, got {other:?}"),
        }
    }
    ledger.drop_guard("admission_operation_recovery_records_no_delete")?;
    ledger
        .connection
        .execute("DELETE FROM admission_operation_recovery_records", [])?;
    match projection_reference(&ledger.connection, "command:c", 1) {
        Err(SqliteServingOwnerError::Invalid(detail)) => assert_eq!(
            detail,
            "recovery record projection reference names an absent record"
        ),
        other => panic!("expected an absent owner refusal, got {other:?}"),
    }
    Ok(())
}
