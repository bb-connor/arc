//! A reading connection whose SQLite length limit is below a stored value
//! still refuses that value with its reader message: the byte ceiling is
//! decided from the record header, so the oversized value is never loaded.

use rusqlite::limits::Limit;
use rusqlite::{params, ErrorCode};

use super::super::digest::is_digest_hex;
use super::super::{
    projection_reference, verify_global_coverage, verify_local_history, RecordKind,
};
use super::encodings::{verify_baseline, ENCODINGS};
use super::fixture::{assert_refused, Ledger, TestResult, SCOPE};

const READ_LENGTH_LIMIT: i32 = 4096;

fn oversized(prefix: &str) -> String {
    format!("{prefix}\0{}", "a".repeat(1_048_576))
}

/// Lower the reading connection's length limit, then show that loading the
/// stored value named by `load` now fails inside SQLite.
fn lower_length_limit_below(ledger: &Ledger, load: &str) -> TestResult {
    ledger
        .connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, READ_LENGTH_LIMIT)?;
    assert_eq!(
        ledger.connection.limit(Limit::SQLITE_LIMIT_LENGTH)?,
        READ_LENGTH_LIMIT
    );
    match ledger
        .connection
        .query_row(load, [], |row| row.get::<_, i64>(0))
    {
        Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == ErrorCode::TooBig => Ok(()),
        other => Err(format!("expected SQLite TOOBIG loading {load:?}, got {other:?}").into()),
    }
}

/// A valid record beside the oversized value still answers an indexed read.
fn assert_reference_reads(ledger: &Ledger, key: &str) -> TestResult {
    let reference = projection_reference(&ledger.connection, key, 1)?;
    assert!(
        is_digest_hex(&reference),
        "{reference} is not a canonical digest"
    );
    Ok(())
}

#[test]
fn oversized_record_text_refuses_from_metadata_under_a_low_length_limit() -> TestResult {
    for encoding in ENCODINGS {
        for column in ["scope_key", "kind", "native_namespace", "native_request"] {
            let mut ledger = Ledger::with_encoding(encoding)?;
            verify_baseline(&mut ledger)?;
            let bad = |name: &str, valid: &str| {
                if name == column {
                    oversized(valid)
                } else {
                    valid.to_owned()
                }
            };
            ledger.set_checks(false)?;
            ledger.connection.execute(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload, native_namespace, native_request)
                 VALUES ('workflow:bad', ?1, ?2, 1, ?3, ?4, ?5)",
                params![
                    bad("scope_key", SCOPE),
                    bad("kind", "workflow"),
                    b"{}".as_slice(),
                    bad("native_namespace", &"cd".repeat(32)),
                    bad("native_request", "request")
                ],
            )?;
            ledger.set_checks(true)?;
            assert!(ledger.checks_enforced()?);
            lower_length_limit_below(
                &ledger,
                &format!(
                    "SELECT length({column}) FROM main.admission_operation_recovery_records
                     WHERE record_key = 'workflow:bad'"
                ),
            )?;
            assert_reference_reads(&ledger, "deployment:baseline")?;
            assert_refused(
                verify_local_history(&ledger.connection),
                "recovery record exceeds its bound",
            );
        }
    }
    Ok(())
}

#[test]
fn oversized_stored_key_refuses_from_metadata_under_a_low_length_limit() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        verify_baseline(&mut ledger)?;
        ledger.set_checks(false)?;
        ledger.write_record(
            SCOPE,
            &oversized("deployment:bad"),
            RecordKind::Deployment,
            b"{}",
            None,
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        lower_length_limit_below(
            &ledger,
            "SELECT max(length(record_key)) FROM main.admission_operation_recovery_records",
        )?;
        assert_reference_reads(&ledger, "deployment:baseline")?;
        assert_refused(
            verify_local_history(&ledger.connection),
            "recovery record stored key exceeds its bound",
        );
    }
    Ok(())
}

#[test]
fn oversized_event_digest_refuses_from_metadata_under_a_low_length_limit() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        verify_baseline(&mut ledger)?;
        ledger.publish("deployment:other", RecordKind::Deployment, b"{}", None)?;
        let sequence = i64::try_from(ledger.sequence() + 1)?;
        let previous = ledger.head().to_owned();
        ledger.set_checks(false)?;
        ledger.connection.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence, record_key, record_version, record_digest, previous_digest,
              event_digest, observed_at)
             VALUES (?1, 'deployment:baseline', 2, ?2, ?3, ?4, ?1)",
            params![
                sequence,
                oversized(&"e".repeat(64)),
                previous,
                "f".repeat(64)
            ],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        lower_length_limit_below(
            &ledger,
            &format!(
                "SELECT length(record_digest) FROM main.admission_operation_recovery_events
                 WHERE sequence = {sequence}"
            ),
        )?;
        assert_reference_reads(&ledger, "deployment:other")?;
        assert_refused(
            verify_local_history(&ledger.connection),
            "recovery history event exceeds its bound",
        );
    }
    Ok(())
}

#[test]
fn oversized_global_reference_refuses_from_metadata_under_a_low_length_limit() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        let published =
            ledger.publish("deployment:baseline", RecordKind::Deployment, b"{}", None)?;
        ledger.install_global_commits()?;
        ledger.commit(1, "deployment:baseline", 1, &published.event_digest)?;
        verify_global_coverage(&ledger.connection)?;
        ledger.connection.execute(
            "UPDATE authority_global_commits SET projection_reference_digest = ?1",
            [oversized(&published.event_digest)],
        )?;
        lower_length_limit_below(
            &ledger,
            "SELECT length(projection_reference_digest) FROM main.authority_global_commits",
        )?;
        assert_reference_reads(&ledger, "deployment:baseline")?;
        verify_local_history(&ledger.connection)?;
        assert_refused(
            verify_global_coverage(&ledger.connection),
            "recovery global commit reference exceeds its bound",
        );
    }
    Ok(())
}
