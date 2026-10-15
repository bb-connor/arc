use rusqlite::types::{ToSqlOutput, Value, ValueRef};

use super::assert_check;
use super::encodings::{
    appended_event_values, assert_unchanged, candidate_values, encoded_catalog, owned_baseline,
    ENCODINGS, INSERT_EVENT, INSERT_RECORD,
};
use super::replacement::{event_snapshot, record_snapshot};
use super::{params, Connection};

/// Blob casts interpret bytes in the database encoding.
const INSERT_CAST_RECORD: &str = "INSERT INTO admission_operation_recovery_records VALUES
     (CAST(?1 AS TEXT), CAST(?2 AS TEXT), ?3, ?4, ?5, CAST(?6 AS TEXT), CAST(?7 AS TEXT))";
const INSERT_CAST_EVENT: &str = "INSERT INTO admission_operation_recovery_events VALUES
     (?1, CAST(?2 AS TEXT), ?3, CAST(?4 AS TEXT), CAST(?5 AS TEXT), CAST(?6 AS TEXT), ?7)";

/// `prefix` characters, then one UTF-8 lead byte whose `continuation` bytes
/// SQLite's `length` folds into a single character, so the text measures
/// `prefix + 1` characters whatever its stored size.
fn malformed_utf8(prefix: &str, continuation: usize) -> Value {
    let mut bytes = prefix.as_bytes().to_vec();
    bytes.push(0xc0);
    bytes.resize(bytes.len() + continuation, 0x80);
    Value::Blob(bytes)
}

fn measured(connection: &Connection, value: &Value) -> rusqlite::Result<(String, i64, i64, i64)> {
    connection.query_row(
        "SELECT typeof(CAST(?1 AS TEXT)), length(CAST(?1 AS TEXT)),
                length(CAST(CAST(?1 AS TEXT) AS BLOB)), instr(CAST(?1 AS TEXT), char(0))",
        [value],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
}

#[test]
fn malformed_utf8_cannot_hide_oversized_record_text() -> rusqlite::Result<()> {
    let connection = owned_baseline("UTF-8")?;
    let records = record_snapshot(&connection)?;
    let events = event_snapshot(&connection)?;
    let scope = malformed_utf8(&"a".repeat(63), 1_048_576);
    assert_eq!(
        measured(&connection, &scope)?,
        ("text".to_owned(), 64, 1_048_640, 0)
    );
    for (column, value) in [
        (0, malformed_utf8(&"k".repeat(511), 2048)),
        (1, scope),
        (5, malformed_utf8(&"d".repeat(63), 256)),
        (6, malformed_utf8(&"r".repeat(255), 1024)),
    ] {
        let mut values = candidate_values();
        values[column] = value;
        assert_check(
            connection.execute(INSERT_CAST_RECORD, rusqlite::params_from_iter(values)),
            "recovery_record_bytes",
        );
        assert_unchanged(&connection, &records, &events)?;
    }
    Ok(())
}

#[test]
fn malformed_utf8_cannot_hide_oversized_event_text() -> rusqlite::Result<()> {
    let connection = owned_baseline("UTF-8")?;
    let records = record_snapshot(&connection)?;
    let events = event_snapshot(&connection)?;
    for (column, value) in [
        (1, malformed_utf8(&"k".repeat(511), 2048)),
        (3, malformed_utf8(&"a".repeat(63), 256)),
        (4, malformed_utf8(&"0".repeat(63), 256)),
        (5, malformed_utf8(&"b".repeat(63), 1_048_576)),
    ] {
        assert_eq!(measured(&connection, &value)?.3, 0);
        let mut values = appended_event_values();
        values[column] = value;
        assert_check(
            connection.execute(INSERT_CAST_EVENT, rusqlite::params_from_iter(values)),
            "recovery_event_bytes",
        );
        assert_unchanged(&connection, &records, &events)?;
    }
    Ok(())
}

#[test]
fn four_byte_codepoints_fill_every_text_ceiling_in_every_encoding() -> rusqlite::Result<()> {
    for encoding in ENCODINGS {
        let connection = encoded_catalog(encoding)?;
        let key = "😀".repeat(512);
        let wide = "😀".repeat(64);
        let request = "😀".repeat(256);
        connection.execute(
            INSERT_RECORD,
            params![key, wide, "workflow", 1, b"{}".as_slice(), wide, request],
        )?;
        connection.execute(INSERT_EVENT, params![1, key, 1, wide, wide, wide, 1])?;
        let record: (i64, i64, i64, i64) = connection.query_row(
            "SELECT length(CAST(record_key AS BLOB)), length(CAST(scope_key AS BLOB)),
                    length(CAST(native_namespace AS BLOB)), length(CAST(native_request AS BLOB))
             FROM admission_operation_recovery_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(record, (2048, 256, 256, 1024));
        let event: (i64, i64, i64, i64) = connection.query_row(
            "SELECT length(CAST(record_key AS BLOB)), length(CAST(record_digest AS BLOB)),
                    length(CAST(previous_digest AS BLOB)), length(CAST(event_digest AS BLOB))
             FROM admission_operation_recovery_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(event, (2048, 256, 256, 256));
    }
    Ok(())
}

/// A UTF-16 catalog translates bound UTF-8 through `READ_UTF8`, which folds
/// the lead byte and all of its continuation bytes into U+FFFD, so the stored
/// text is well-formed and inside every ceiling.
#[test]
fn utf16_catalogs_store_malformed_utf8_as_one_replacement_character() -> rusqlite::Result<()> {
    for encoding in ["UTF-16le", "UTF-16be"] {
        let connection = owned_baseline(encoding)?;
        let mut record = candidate_values();
        record[0] = malformed_utf8(&"k".repeat(511), 2048);
        record[1] = malformed_utf8(&"a".repeat(63), 1_048_576);
        record[5] = malformed_utf8(&"d".repeat(63), 256);
        record[6] = malformed_utf8(&"r".repeat(255), 1024);
        let records = record_snapshot(&connection)?;
        let events = event_snapshot(&connection)?;
        assert_check(
            connection.execute(INSERT_CAST_RECORD, rusqlite::params_from_iter(&record)),
            "length(record_key) BETWEEN 1 AND 512",
        );
        assert_unchanged(&connection, &records, &events)?;
        let mut bound = record.each_ref().map(ToSqlOutput::from);
        for column in [0, 1, 5, 6] {
            let Value::Blob(bytes) = &record[column] else {
                panic!("malformed text fixture must contain raw bytes");
            };
            bound[column] = ToSqlOutput::Borrowed(ValueRef::Text(bytes));
        }
        connection.execute(INSERT_RECORD, rusqlite::params_from_iter(bound))?;
        let key = format!("{}\u{fffd}", "k".repeat(511));
        let stored: (String, String, String, String, i64, i64, i64, i64) = connection.query_row(
            "SELECT record_key, scope_key, native_namespace, native_request,
                    length(CAST(record_key AS BLOB)), length(CAST(scope_key AS BLOB)),
                    length(CAST(native_namespace AS BLOB)), length(CAST(native_request AS BLOB))
             FROM admission_operation_recovery_records WHERE record_key <> 'key'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )?;
        assert_eq!(
            stored,
            (
                key.clone(),
                format!("{}\u{fffd}", "a".repeat(63)),
                format!("{}\u{fffd}", "d".repeat(63)),
                format!("{}\u{fffd}", "r".repeat(255)),
                1024,
                128,
                128,
                512
            )
        );
        let mut event = appended_event_values();
        event[1] = Value::Text(key);
        event[5] = malformed_utf8(&"b".repeat(63), 1_048_576);
        let mut bound = event.each_ref().map(ToSqlOutput::from);
        let Value::Blob(bytes) = &event[5] else {
            panic!("malformed text fixture must contain raw bytes");
        };
        bound[5] = ToSqlOutput::Borrowed(ValueRef::Text(bytes));
        connection.execute(INSERT_EVENT, rusqlite::params_from_iter(bound))?;
        let digest: (String, i64) = connection.query_row(
            "SELECT event_digest, length(CAST(event_digest AS BLOB))
             FROM admission_operation_recovery_events WHERE sequence = 9",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(digest, (format!("{}\u{fffd}", "b".repeat(63)), 128));
    }
    Ok(())
}
