//! Stored values inside their text bounds but outside their semantic domain,
//! seeded through the real catalog with CHECKs disabled and restored before
//! every read. Each value is built so that its digests agree with it, so the
//! asserted refusal comes from the value check rather than a digest mismatch.

use rusqlite::params;
use rusqlite::types::Value;

use super::super::digest::{event_digest, EventDigestInput};
use super::super::{verify_local_history, NativeIdentity, RecordKind};
use super::fixture::{assert_refused, EventSeed, Ledger, TestResult, SCOPE};

#[test]
fn native_identity_on_a_non_workflow_record_refuses() -> TestResult {
    let ledger = Ledger::new()?;
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: "request-1".to_owned(),
    };
    ledger.set_checks(false)?;
    ledger.write_record(
        SCOPE,
        "command:c",
        RecordKind::Command,
        b"{}",
        Some(&native),
    )?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record native identity is malformed",
    );
    Ok(())
}

#[test]
fn stored_record_versions_outside_the_safe_integer_domain_refuse() -> TestResult {
    for (version, expected) in [
        (Value::Integer(0), "recovery record version is out of range"),
        (
            Value::Integer(9_007_199_254_740_992),
            "recovery record version is out of range",
        ),
        (Value::Integer(-1), "recovery record version is negative"),
        (Value::Real(1.5), "recovery record exceeds its bound"),
        (
            Value::Text("one".to_owned()),
            "recovery record exceeds its bound",
        ),
    ] {
        let ledger = Ledger::new()?;
        ledger.set_checks(false)?;
        ledger.connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES ('deployment:a', ?1, 'deployment', ?2, ?3)",
            params![SCOPE, version, b"{}".as_slice()],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(verify_local_history(&ledger.connection), expected);
    }
    Ok(())
}

/// The numeric fields an event stores, and the values its digest binds. A
/// non-integer is bound as 0, the value the bounded SELECT reads it as.
struct BadEvent {
    sequence: Value,
    version: Value,
    observed: Value,
    digested: (u64, u64, u64),
}

#[test]
fn stored_event_numbers_outside_the_safe_integer_domain_refuse() -> TestResult {
    for bad in [
        BadEvent {
            sequence: Value::Integer(0),
            version: Value::Integer(1),
            observed: Value::Integer(2),
            digested: (0, 1, 2),
        },
        BadEvent {
            sequence: Value::Integer(2),
            version: Value::Integer(0),
            observed: Value::Integer(2),
            digested: (2, 0, 2),
        },
        BadEvent {
            sequence: Value::Integer(2),
            version: Value::Real(1.5),
            observed: Value::Integer(2),
            digested: (2, 0, 2),
        },
        BadEvent {
            sequence: Value::Integer(2),
            version: Value::Integer(1),
            observed: Value::Integer(0),
            digested: (2, 1, 0),
        },
        BadEvent {
            sequence: Value::Integer(2),
            version: Value::Integer(1),
            observed: Value::Text("later".to_owned()),
            digested: (2, 1, 0),
        },
    ] {
        let mut ledger = Ledger::new()?;
        ledger.publish("deployment:a", RecordKind::Deployment, b"{}", None)?;
        verify_local_history(&ledger.connection)?;
        let record_digest = "e".repeat(64);
        let previous = ledger.head().to_owned();
        let (sequence, version, observed) = bad.digested;
        let stored_digest = event_digest(&EventDigestInput {
            sequence,
            key: "deployment:z",
            version,
            record_digest: &record_digest,
            previous_digest: &previous,
            observed_at: observed,
        })?;
        ledger.set_checks(false)?;
        ledger.connection.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence, record_key, record_version, record_digest, previous_digest,
              event_digest, observed_at)
             VALUES (?1, 'deployment:z', ?2, ?3, ?4, ?5, ?6)",
            params![
                bad.sequence,
                bad.version,
                record_digest,
                previous,
                stored_digest,
                bad.observed
            ],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(
            verify_local_history(&ledger.connection),
            "recovery history event is corrupt",
        );
    }
    Ok(())
}

/// Write version 2 of `deployment:a` and append its event, uppercasing the
/// record digest or the previous digest. The event digest is computed over
/// the uppercased value, so only the canonical-hex check can refuse it.
fn append_uppercase(
    ledger: &mut Ledger,
    upper_record: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ledger.write_record(
        SCOPE,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":2}"#,
        None,
    )?;
    let mut record_digest =
        ledger.current_digest("deployment:a", RecordKind::Deployment, br#"{"v":2}"#)?;
    let mut previous = ledger.head().to_owned();
    let target = if upper_record {
        &mut record_digest
    } else {
        &mut previous
    };
    let upper = target.to_ascii_uppercase();
    assert_ne!(*target, upper, "the digest has no hex letter to uppercase");
    *target = upper;
    ledger.set_checks(false)?;
    ledger.append_event(&EventSeed {
        sequence: 2,
        key: "deployment:a",
        version: 2,
        record_digest: &record_digest,
        previous: &previous,
        observed: 2,
    })?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    Ok(())
}

#[test]
fn uppercase_event_record_digest_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    append_uppercase(&mut ledger, true)?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history event is corrupt",
    );
    Ok(())
}

#[test]
fn uppercase_event_previous_digest_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    append_uppercase(&mut ledger, false)?;
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history event is corrupt",
    );
    Ok(())
}
