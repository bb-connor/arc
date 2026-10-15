//! Malformed stored text within its byte ceiling reaches materialization and
//! is refused by the shared SQLite error mapping as an exact invariant. Beyond
//! the ceiling it is refused before materialization.

use rusqlite::params;

use super::super::{verify_global_coverage, verify_local_history, RecordKind};
use super::encodings::{verify_baseline, ENCODINGS};
use super::fixture::{assert_refused, Ledger, TestResult, SCOPE};

/// `count` copies of the ASCII `prefix`, then one invalid unit, as stored
/// bytes of `encoding`. UTF-8 stores an overlong `C0 80`; UTF-16 stores a
/// trailing lone high surrogate, which the bundled SQLite (built without
/// `SQLITE_REPLACE_INVALID_UTF`) translates to the UTF-8 bytes `ED A0 80`.
/// A blob literal takes the database encoding, so the CAST keeps these bytes.
fn malformed_literal(encoding: &str, prefix: u8, count: usize) -> String {
    let (unit, invalid) = match encoding {
        "UTF-8" => (format!("{prefix:02X}"), "C080"),
        "UTF-16le" => (format!("{prefix:02X}00"), "00D8"),
        _ => (format!("00{prefix:02X}"), "D800"),
    };
    format!("CAST(x'{}{invalid}' AS TEXT)", unit.repeat(count))
}

/// The rusqlite conversion failure that `sqlite_error` maps to an invariant.
fn conversion_refusal(valid_prefix: usize, column: usize) -> String {
    format!("invalid utf-8 sequence of 1 bytes from index {valid_prefix} at index {column}")
}

fn measured(ledger: &Ledger, expression: &str) -> rusqlite::Result<(i64, i64)> {
    ledger.connection.query_row(
        &format!("SELECT length({expression}), octet_length({expression})"),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
}

fn unit_bytes(encoding: &str) -> i64 {
    if encoding == "UTF-8" {
        1
    } else {
        2
    }
}

#[test]
fn malformed_record_scope_within_its_ceiling_refuses_on_conversion() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        verify_baseline(&mut ledger)?;
        let scope = malformed_literal(encoding, b'a', 63);
        let (characters, bytes) = measured(&ledger, &scope)?;
        assert_eq!(characters, 64);
        assert!(bytes <= 256 && bytes > 63 * unit_bytes(encoding));
        ledger.set_checks(false)?;
        ledger.connection.execute(
            &format!(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload)
                 VALUES ('workflow:bad', {scope}, 'deployment', 1, ?1)"
            ),
            [b"{}".as_slice()],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(
            verify_local_history(&ledger.connection),
            &conversion_refusal(63, 2),
        );
    }
    Ok(())
}

#[test]
fn malformed_stored_key_within_its_ceiling_refuses_on_conversion() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        verify_baseline(&mut ledger)?;
        let key = malformed_literal(encoding, b'k', 511);
        assert_eq!(measured(&ledger, &key)?.0, 512);
        ledger.set_checks(false)?;
        ledger.connection.execute(
            &format!(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload)
                 VALUES ({key}, ?1, 'deployment', 1, ?2)"
            ),
            params![SCOPE, b"{}".as_slice()],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(
            verify_local_history(&ledger.connection),
            &conversion_refusal(511, 0),
        );
    }
    Ok(())
}

#[test]
fn malformed_event_digest_within_its_ceiling_refuses_on_conversion() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        verify_baseline(&mut ledger)?;
        let digest = malformed_literal(encoding, b'e', 63);
        let previous = ledger.head().to_owned();
        ledger.set_checks(false)?;
        ledger.connection.execute(
            &format!(
                "INSERT INTO admission_operation_recovery_events
                 (sequence, record_key, record_version, record_digest, previous_digest,
                  event_digest, observed_at)
                 VALUES (2, 'deployment:baseline', 2, {digest}, ?1, ?2, 2)"
            ),
            params![previous, "f".repeat(64)],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(
            verify_local_history(&ledger.connection),
            &conversion_refusal(63, 3),
        );
    }
    Ok(())
}

#[test]
fn malformed_global_reference_within_its_ceiling_refuses_on_conversion() -> TestResult {
    for encoding in ENCODINGS {
        let mut ledger = Ledger::with_encoding(encoding)?;
        let published = ledger.publish("command:a", RecordKind::Command, b"{}", None)?;
        ledger.install_global_commits()?;
        ledger.commit(1, "command:a", 1, &published.event_digest)?;
        verify_global_coverage(&ledger.connection)?;
        ledger.connection.execute(
            &format!(
                "UPDATE authority_global_commits SET projection_reference_digest = {}",
                malformed_literal(encoding, b'e', 63)
            ),
            [],
        )?;
        assert_refused(
            verify_global_coverage(&ledger.connection),
            &conversion_refusal(63, 1),
        );
        verify_local_history(&ledger.connection)?;
    }
    Ok(())
}

/// UTF-8 text whose `length` counts `prefix + 1` characters while it stores
/// `prefix + 1 + continuation` bytes.
fn malformed_utf8(prefix: u8, count: usize, continuation: usize) -> Vec<u8> {
    let mut bytes = vec![prefix; count];
    bytes.push(0xc0);
    bytes.extend(std::iter::repeat_n(0x80, continuation));
    bytes
}

#[test]
fn malformed_utf8_key_and_request_refuse_exactly_beyond_their_byte_ceilings() -> TestResult {
    for (continuation, refusal) in [
        (1536, conversion_refusal(511, 0)),
        (
            1537,
            "recovery record stored key exceeds its bound".to_owned(),
        ),
    ] {
        let mut ledger = Ledger::with_encoding("UTF-8")?;
        verify_baseline(&mut ledger)?;
        let key = malformed_utf8(b'k', 511, continuation);
        let (characters, bytes): (i64, i64) = ledger.connection.query_row(
            "SELECT length(CAST(?1 AS TEXT)), length(?1)",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(characters, 512);
        assert_eq!(bytes, 512 + i64::try_from(continuation)?);
        ledger.set_checks(false)?;
        ledger.connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES (CAST(?1 AS TEXT), ?2, 'deployment', 1, ?3)",
            params![key, SCOPE, b"{}".as_slice()],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(verify_local_history(&ledger.connection), &refusal);
    }
    for (continuation, refusal) in [
        (768, conversion_refusal(255, 8)),
        (769, "recovery record exceeds its bound".to_owned()),
    ] {
        let mut ledger = Ledger::with_encoding("UTF-8")?;
        verify_baseline(&mut ledger)?;
        let request = malformed_utf8(b'r', 255, continuation);
        ledger.set_checks(false)?;
        ledger.connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload, native_namespace, native_request)
             VALUES ('workflow:bad', ?1, 'workflow', 1, ?2, ?3, CAST(?4 AS TEXT))",
            params![SCOPE, b"{}".as_slice(), "cd".repeat(32), request],
        )?;
        ledger.set_checks(true)?;
        assert!(ledger.checks_enforced()?);
        assert_refused(verify_local_history(&ledger.connection), &refusal);
    }
    Ok(())
}
