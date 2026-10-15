use rusqlite::types::Value;

use super::bounds::{event_values, record_values};
use super::replacement::{event_snapshot, record_snapshot};
use super::{assert_check, assert_trigger_refusal, params, Connection, RECORDS};

pub(super) const ENCODINGS: [&str; 3] = ["UTF-8", "UTF-16le", "UTF-16be"];
const UTF16: [&str; 2] = ["UTF-16le", "UTF-16be"];
pub(super) const INSERT_RECORD: &str =
    "INSERT INTO admission_operation_recovery_records VALUES (?1,?2,?3,?4,?5,?6,?7)";
pub(super) const INSERT_EVENT: &str =
    "INSERT INTO admission_operation_recovery_events VALUES (?1,?2,?3,?4,?5,?6,?7)";

/// A fresh catalog whose text encoding is fixed before its first table.
pub(super) fn encoded_catalog(encoding: &str) -> rusqlite::Result<Connection> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&format!(
        "PRAGMA encoding = '{encoding}'; PRAGMA foreign_keys = ON;"
    ))?;
    connection.execute_batch(RECORDS)?;
    let actual: String = connection.query_row("PRAGMA encoding", [], |row| row.get(0))?;
    assert_eq!(actual, encoding);
    Ok(connection)
}

/// One owned workflow record with its native identity and first event.
pub(super) fn owned_baseline(encoding: &str) -> rusqlite::Result<Connection> {
    let connection = encoded_catalog(encoding)?;
    connection.execute(INSERT_RECORD, rusqlite::params_from_iter(record_values()))?;
    connection.execute(INSERT_EVENT, rusqlite::params_from_iter(event_values()))?;
    Ok(connection)
}

/// A record that conflicts with no owned key or native identity.
pub(super) fn candidate_values() -> [Value; 7] {
    let mut values = record_values();
    values[0] = Value::Text("candidate".to_owned());
    values[5] = Value::Text("d".repeat(64));
    values[6] = Value::Text("other".to_owned());
    values
}

/// An event that conflicts with no retained sequence or record version.
pub(super) fn appended_event_values() -> [Value; 7] {
    let mut values = event_values();
    values[0] = Value::Integer(9);
    values[2] = Value::Integer(9);
    values
}

pub(super) fn assert_unchanged(
    connection: &Connection,
    records: &[String],
    events: &[String],
) -> rusqlite::Result<()> {
    assert_eq!(record_snapshot(connection)?, records);
    assert_eq!(event_snapshot(connection)?, events);
    Ok(())
}

#[test]
fn valid_ascii_and_multibyte_identities_round_trip_in_every_encoding() -> rusqlite::Result<()> {
    for encoding in ENCODINGS {
        let connection = owned_baseline(encoding)?;
        assert_eq!(
            connection.execute(
                "UPDATE admission_operation_recovery_records
                 SET payload = ?1, version = 2 WHERE record_key = 'key'",
                [br#"{"updated":true}"#.as_slice()],
            )?,
            1
        );
        connection.execute(
            "INSERT INTO admission_operation_recovery_events VALUES (2,'key',2,?1,?2,?3,2)",
            params!["c".repeat(64), "b".repeat(64), "d".repeat(64)],
        )?;
        let key = "😀".repeat(512);
        let request = "😀".repeat(256);
        connection.execute(
            "INSERT INTO admission_operation_recovery_records VALUES (?1,?2,'workflow',1,?3,?4,?5)",
            params![
                key,
                "a".repeat(64),
                b"{}".as_slice(),
                "e".repeat(64),
                request
            ],
        )?;
        connection.execute(
            "INSERT INTO admission_operation_recovery_events VALUES (3,?1,1,?2,?3,?4,3)",
            params![key, "a".repeat(64), "0".repeat(64), "f".repeat(64)],
        )?;
        connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES ('maximum', ?1, 'deployment', 1, ?2)",
            params!["a".repeat(64), vec![b'x'; 262144]],
        )?;
        let stored: (String, String, String, i64) = connection.query_row(
            "SELECT record_key, native_namespace, native_request, length(record_key)
             FROM admission_operation_recovery_records WHERE native_namespace = ?1",
            ["e".repeat(64)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(stored, (key.clone(), "e".repeat(64), request, 512));
        let digests: (String, String, String) = connection.query_row(
            "SELECT record_digest, previous_digest, event_digest
             FROM admission_operation_recovery_events WHERE sequence = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(digests, ("c".repeat(64), "b".repeat(64), "d".repeat(64)));
        let (version, payload_bytes): (i64, i64) = connection.query_row(
            "SELECT version, length(payload) FROM admission_operation_recovery_records
             WHERE record_key = 'key'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((version, payload_bytes), (2, 16));
        let maximum: i64 = connection.query_row(
            "SELECT length(payload) FROM admission_operation_recovery_records
             WHERE record_key = 'maximum'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(maximum, 262144);
        let records = record_snapshot(&connection)?;
        let events = event_snapshot(&connection)?;
        for (key, length) in [("empty", 0), ("oversized", 262145)] {
            assert_check(
                connection.execute(
                    "INSERT INTO admission_operation_recovery_records
                     (record_key, scope_key, kind, version, payload)
                     VALUES (?1, ?2, 'deployment', 1, ?3)",
                    params![key, "a".repeat(64), vec![b'x'; length]],
                ),
                "length(payload) BETWEEN 1 AND 262144",
            );
            assert_unchanged(&connection, &records, &events)?;
        }
    }
    Ok(())
}

#[test]
fn utf16_catalogs_refuse_a_nul_suffix_on_every_text_column() -> rusqlite::Result<()> {
    for encoding in UTF16 {
        let connection = owned_baseline(encoding)?;
        let records = record_snapshot(&connection)?;
        let events = event_snapshot(&connection)?;
        for (column, value, constraint) in [
            (
                0,
                format!("candidate\0{}", "x".repeat(2048)),
                "recovery_record_text",
            ),
            (
                1,
                format!("{}\0{}", "a".repeat(64), "x".repeat(64)),
                "recovery_record_text",
            ),
            (
                2,
                "workflow\0".to_owned(),
                "kind IN ('deployment', 'workflow', 'command')",
            ),
            (
                5,
                format!("{}\0{}", "d".repeat(64), "x".repeat(64)),
                "recovery_record_text",
            ),
            (6, "other\0suffix".to_owned(), "recovery_record_text"),
        ] {
            let mut values = candidate_values();
            values[column] = Value::Text(value);
            assert_check(
                connection.execute(INSERT_RECORD, rusqlite::params_from_iter(values)),
                constraint,
            );
            assert_unchanged(&connection, &records, &events)?;
        }
        for (column, value) in [
            (1, format!("key\0{}", "x".repeat(2048))),
            (3, format!("{}\0{}", "a".repeat(64), "x".repeat(64))),
            (4, format!("{}\0{}", "0".repeat(64), "x".repeat(64))),
            (5, format!("{}\0{}", "b".repeat(64), "x".repeat(64))),
        ] {
            let mut values = appended_event_values();
            values[column] = Value::Text(value);
            assert_check(
                connection.execute(INSERT_EVENT, rusqlite::params_from_iter(values)),
                "recovery_event_text",
            );
            assert_unchanged(&connection, &records, &events)?;
        }
    }
    Ok(())
}

#[test]
fn utf16_catalogs_refuse_wrong_storage_classes() -> rusqlite::Result<()> {
    for encoding in UTF16 {
        let connection = owned_baseline(encoding)?;
        let records = record_snapshot(&connection)?;
        let events = event_snapshot(&connection)?;
        for (column, value) in [
            (0, Value::Blob(b"candidate".to_vec())),
            (1, Value::Blob(vec![b'a'; 64])),
            (3, Value::Real(1.5)),
            (4, Value::Text("{}".to_owned())),
            (5, Value::Blob(vec![b'd'; 64])),
            (6, Value::Blob(b"other".to_vec())),
        ] {
            let mut values = candidate_values();
            values[column] = value;
            assert_check(
                connection.execute(INSERT_RECORD, rusqlite::params_from_iter(values)),
                "recovery_record_storage",
            );
            assert_unchanged(&connection, &records, &events)?;
        }
        for (column, value) in [
            (1, Value::Blob(b"key".to_vec())),
            (3, Value::Blob(vec![b'a'; 64])),
            (4, Value::Blob(vec![b'0'; 64])),
            (5, Value::Blob(vec![b'b'; 64])),
            (6, Value::Real(1.5)),
        ] {
            let mut values = appended_event_values();
            values[column] = value;
            assert_check(
                connection.execute(INSERT_EVENT, rusqlite::params_from_iter(values)),
                "recovery_event_storage",
            );
            assert_unchanged(&connection, &records, &events)?;
        }
    }
    Ok(())
}

#[test]
fn utf16_catalogs_refuse_codepoints_beyond_each_bound() -> rusqlite::Result<()> {
    for encoding in UTF16 {
        let connection = owned_baseline(encoding)?;
        let records = record_snapshot(&connection)?;
        let events = event_snapshot(&connection)?;
        for (column, value, constraint) in [
            (0, "😀".repeat(513), "length(record_key) BETWEEN 1 AND 512"),
            (1, "a".repeat(65), "length(scope_key) = 64"),
            (
                5,
                "d".repeat(63),
                "native_namespace IS NULL OR length(native_namespace) = 64",
            ),
            (
                6,
                "😀".repeat(257),
                "native_request IS NULL OR length(native_request) BETWEEN 1 AND 256",
            ),
        ] {
            let mut values = candidate_values();
            values[column] = Value::Text(value);
            assert_check(
                connection.execute(INSERT_RECORD, rusqlite::params_from_iter(values)),
                constraint,
            );
            assert_unchanged(&connection, &records, &events)?;
        }
        for (column, value, constraint) in [
            (1, "😀".repeat(513), "length(record_key) BETWEEN 1 AND 512"),
            (3, "a".repeat(65), "length(record_digest) = 64"),
            (4, "0".repeat(63), "length(previous_digest) = 64"),
            (5, "😀".repeat(65), "length(event_digest) = 64"),
        ] {
            let mut values = appended_event_values();
            values[column] = Value::Text(value);
            assert_check(
                connection.execute(INSERT_EVENT, rusqlite::params_from_iter(values)),
                constraint,
            );
            assert_unchanged(&connection, &records, &events)?;
        }
    }
    Ok(())
}

#[test]
fn utf16_catalogs_keep_ownership_and_history_immutable() -> rusqlite::Result<()> {
    for encoding in UTF16 {
        let connection = owned_baseline(encoding)?;
        connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES ('candidate', ?1, 'workflow', 1, ?2)",
            params!["a".repeat(64), b"{}".as_slice()],
        )?;
        let records = record_snapshot(&connection)?;
        let events = event_snapshot(&connection)?;
        let refusals: [(&str, Vec<Value>, &str); 8] = [
            (
                "INSERT OR REPLACE INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload)
                 VALUES ('key', ?1, 'deployment', 1, ?2)",
                vec![Value::Text("a".repeat(64)), Value::Blob(b"{}".to_vec())],
                "recovery ownership cannot be replaced",
            ),
            (
                "INSERT INTO admission_operation_recovery_records VALUES
                 ('third', ?1, 'workflow', 1, ?2, ?3, 'request')",
                vec![
                    Value::Text("a".repeat(64)),
                    Value::Blob(b"{}".to_vec()),
                    Value::Text("b".repeat(64)),
                ],
                "recovery ownership cannot be replaced",
            ),
            (
                "UPDATE OR REPLACE admission_operation_recovery_records
                 SET native_namespace = ?1, native_request = 'request', version = 2
                 WHERE record_key = 'candidate'",
                vec![Value::Text("b".repeat(64))],
                "recovery native identity already has an owner",
            ),
            (
                "UPDATE admission_operation_recovery_records
                 SET scope_key = ?1, version = 2 WHERE record_key = 'key'",
                vec![Value::Text("c".repeat(64))],
                "recovery identity is immutable",
            ),
            (
                "DELETE FROM admission_operation_recovery_records WHERE record_key = 'candidate'",
                Vec::new(),
                "recovery ownership cannot be deleted",
            ),
            (
                "INSERT OR REPLACE INTO admission_operation_recovery_events
                 VALUES (1, 'key', 2, ?1, ?2, ?3, 2)",
                vec![
                    Value::Text("c".repeat(64)),
                    Value::Text("0".repeat(64)),
                    Value::Text("d".repeat(64)),
                ],
                "recovery history cannot be replaced",
            ),
            (
                "UPDATE admission_operation_recovery_events SET observed_at = 2",
                Vec::new(),
                "recovery history is immutable",
            ),
            (
                "DELETE FROM admission_operation_recovery_events",
                Vec::new(),
                "recovery history cannot be deleted",
            ),
        ];
        for (statement, values, message) in refusals {
            assert_trigger_refusal(
                connection.execute(statement, rusqlite::params_from_iter(values)),
                message,
            );
            assert_unchanged(&connection, &records, &events)?;
        }
    }
    Ok(())
}
