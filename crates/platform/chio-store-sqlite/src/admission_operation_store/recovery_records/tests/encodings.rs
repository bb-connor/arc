//! Protected reads retain the same text bounds in every SQLite encoding.

use rusqlite::params;

use super::super::{
    projection_reference, verify_global_coverage, verify_local_history, NativeIdentity, RecordKind,
};
use super::fixture::{assert_refused, EventSeed, Ledger, TestResult, SCOPE};

pub(super) const ENCODINGS: [&str; 3] = ["UTF-8", "UTF-16le", "UTF-16be"];

pub(super) fn verify_baseline(ledger: &mut Ledger) -> TestResult {
    ledger.publish("deployment:baseline", RecordKind::Deployment, b"{}", None)?;
    verify_local_history(&ledger.connection)?;
    Ok(())
}

#[test]
fn encoded_native_records_authenticate_updates_and_both_histories() -> TestResult {
    for encoding in ENCODINGS {
        for (key, request) in [
            ("workflow:ascii".to_owned(), "request-ascii".to_owned()),
            ("é".repeat(512), "é".repeat(256)),
            ("\u{1F642}".repeat(512), "\u{1F642}".repeat(256)),
        ] {
            let mut ledger = Ledger::with_encoding(encoding)?;
            ledger.install_global_commits()?;
            let native = NativeIdentity {
                namespace: "cd".repeat(32),
                request,
            };
            for version in 1..=2 {
                let payload = format!("{{\"version\":{version}}}");
                let event = ledger.publish(
                    &key,
                    RecordKind::Workflow,
                    payload.as_bytes(),
                    Some(&native),
                )?;
                ledger.commit(i64::try_from(version)?, &key, version, &event.event_digest)?;
                assert_eq!(
                    projection_reference(&ledger.connection, &key, version)?,
                    event.event_digest
                );
                verify_local_history(&ledger.connection)?;
                verify_global_coverage(&ledger.connection)?;
            }
        }
    }
    Ok(())
}

#[test]
fn encoded_nul_and_overlong_native_requests_refuse_in_select() -> TestResult {
    for encoding in ENCODINGS {
        for request in [
            "request\0hidden".to_owned(),
            format!("r\0{}", "a".repeat(1_048_576)),
            "a".repeat(257),
            "\u{1F642}".repeat(257),
        ] {
            let mut ledger = Ledger::with_encoding(encoding)?;
            verify_baseline(&mut ledger)?;
            let native = NativeIdentity {
                namespace: "cd".repeat(32),
                request,
            };
            ledger.set_checks(false)?;
            ledger.write_record(
                SCOPE,
                "workflow:bad",
                RecordKind::Workflow,
                b"{}",
                Some(&native),
            )?;
            ledger.set_checks(true)?;
            assert!(ledger.checks_enforced()?);
            assert_refused(
                verify_local_history(&ledger.connection),
                "recovery record exceeds its bound",
            );
        }
    }
    Ok(())
}

#[test]
fn encoded_nul_scope_and_namespace_refuse_in_select() -> TestResult {
    for encoding in ENCODINGS {
        for corrupt_scope in [true, false] {
            let mut ledger = Ledger::with_encoding(encoding)?;
            verify_baseline(&mut ledger)?;
            let bad = format!("{SCOPE}\0{}", "a".repeat(1_048_576));
            let scope = if corrupt_scope { bad.as_str() } else { SCOPE };
            let native = NativeIdentity {
                namespace: if corrupt_scope {
                    "cd".repeat(32)
                } else {
                    bad.clone()
                },
                request: "request".to_owned(),
            };
            ledger.set_checks(false)?;
            ledger.write_record(
                scope,
                "workflow:bad",
                RecordKind::Workflow,
                b"{}",
                Some(&native),
            )?;
            ledger.set_checks(true)?;
            assert!(ledger.checks_enforced()?);
            assert_refused(
                verify_local_history(&ledger.connection),
                "recovery record exceeds its bound",
            );
        }
    }
    Ok(())
}

#[test]
fn encoded_nul_and_overlong_stored_keys_refuse_before_materialization() -> TestResult {
    for encoding in ENCODINGS {
        for key in [
            format!("deployment:bad\0{}", "a".repeat(1_048_576)),
            "a".repeat(513),
            "\u{1F642}".repeat(513),
        ] {
            let mut ledger = Ledger::with_encoding(encoding)?;
            verify_baseline(&mut ledger)?;
            ledger.set_checks(false)?;
            ledger.write_record(SCOPE, &key, RecordKind::Deployment, b"{}", None)?;
            ledger.set_checks(true)?;
            assert!(ledger.checks_enforced()?);
            assert_refused(
                verify_local_history(&ledger.connection),
                "recovery record stored key exceeds its bound",
            );
        }
    }
    Ok(())
}

#[test]
fn encoded_nul_event_digests_refuse_in_select() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        verify_baseline(&mut ledger)?;
        ledger.write_record(
            SCOPE,
            "deployment:baseline",
            RecordKind::Deployment,
            br#"{"v":2}"#,
            None,
        )?;
        let previous = ledger.head().to_owned();
        let bad = format!("{}\0{}", "e".repeat(64), "a".repeat(1_048_576));
        ledger.set_checks(false)?;
        ledger.append_event(&EventSeed {
            sequence: 2,
            key: "deployment:baseline",
            version: 2,
            record_digest: &bad,
            previous: &previous,
            observed: 2,
        })?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(
            verify_local_history(&ledger.connection),
            "recovery history event exceeds its bound",
        );
    }
    Ok(())
}

#[test]
fn encoded_nul_global_references_refuse_in_select() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        let published = ledger.publish("command:a", RecordKind::Command, b"{}", None)?;
        ledger.install_global_commits()?;
        ledger.commit(1, "command:a", 1, &published.event_digest)?;
        verify_local_history(&ledger.connection)?;
        verify_global_coverage(&ledger.connection)?;
        let bad = format!("{}\0{}", published.event_digest, "a".repeat(1_048_576));
        ledger.connection.execute(
            "UPDATE authority_global_commits SET projection_reference_digest = ?1",
            [bad],
        )?;
        assert_refused(
            verify_global_coverage(&ledger.connection),
            "recovery global commit reference exceeds its bound",
        );
        verify_local_history(&ledger.connection)?;
    }
    Ok(())
}

#[test]
fn malformed_utf8_scope_refuses_before_materialization() -> TestResult {
    let mut ledger = Ledger::with_encoding("UTF-8")?;
    verify_baseline(&mut ledger)?;
    let mut malformed = vec![b'a'; 63];
    malformed.push(0xc0);
    malformed.extend(std::iter::repeat_n(0x80, 1_048_576));
    let (characters, bytes): (i64, i64) = ledger.connection.query_row(
        "SELECT length(CAST(?1 AS TEXT)), length(?1)",
        [&malformed],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(characters, 64);
    assert_eq!(bytes, 1_048_640);
    ledger.set_checks(false)?;
    ledger.connection.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES ('deployment:bad', CAST(?1 AS TEXT), 'deployment', 1, ?2)",
        params![malformed, b"{}".as_slice()],
    )?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record exceeds its bound",
    );
    Ok(())
}
