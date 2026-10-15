use rusqlite::types::Value;

use super::{assert_check, params, record, Connection, RECORDS};

pub(super) fn record_values() -> [Value; 7] {
    [
        Value::Text("key".to_owned()),
        Value::Text("a".repeat(64)),
        Value::Text("workflow".to_owned()),
        Value::Integer(1),
        Value::Blob(b"{}".to_vec()),
        Value::Text("b".repeat(64)),
        Value::Text("request".to_owned()),
    ]
}

pub(super) fn event_values() -> [Value; 7] {
    [
        Value::Integer(1),
        Value::Text("key".to_owned()),
        Value::Integer(1),
        Value::Text("a".repeat(64)),
        Value::Text("0".repeat(64)),
        Value::Text("b".repeat(64)),
        Value::Integer(1),
    ]
}

fn empty_count(connection: &Connection, table: &str) -> rusqlite::Result<()> {
    let count: i64 = connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn embedded_nul_cannot_hide_oversized_record_identity() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    for (column, value) in [
        (0, format!("key\0{}", "x".repeat(2048))),
        (1, format!("{}\0{}", "a".repeat(64), "x".repeat(4096))),
        (5, format!("{}\0{}", "b".repeat(64), "x".repeat(4096))),
        (6, format!("request\0{}", "x".repeat(1024))),
    ] {
        let mut values = record_values();
        values[column] = Value::Text(value);
        assert_check(
            connection.execute(
                "INSERT INTO admission_operation_recovery_records VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params_from_iter(values),
            ),
            "recovery_record_text",
        );
        empty_count(&connection, "admission_operation_recovery_records")?;
    }
    Ok(())
}

#[test]
fn embedded_nul_cannot_hide_oversized_event_fields() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "key", "deployment")?;
    for (column, value) in [
        (1, format!("key\0{}", "x".repeat(2048))),
        (3, format!("{}\0{}", "a".repeat(64), "x".repeat(4096))),
        (4, format!("{}\0{}", "0".repeat(64), "x".repeat(4096))),
        (5, format!("{}\0{}", "b".repeat(64), "x".repeat(4096))),
    ] {
        let mut values = event_values();
        values[column] = Value::Text(value);
        assert_check(
            connection.execute(
                "INSERT INTO admission_operation_recovery_events VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params_from_iter(values),
            ),
            "recovery_event_text",
        );
        empty_count(&connection, "admission_operation_recovery_events")?;
    }
    Ok(())
}

#[test]
fn record_columns_require_their_declared_storage_types() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    for (column, value) in [
        (0, Value::Blob(b"key".to_vec())),
        (1, Value::Blob(vec![b'a'; 64])),
        (3, Value::Real(1.5)),
        (4, Value::Text(format!("{{}}\0{}", "x".repeat(262145)))),
        (5, Value::Blob(vec![b'b'; 64])),
        (6, Value::Blob(b"request".to_vec())),
    ] {
        let mut values = record_values();
        values[column] = value;
        assert_check(
            connection.execute(
                "INSERT INTO admission_operation_recovery_records VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params_from_iter(values),
            ),
            "recovery_record_storage",
        );
        empty_count(&connection, "admission_operation_recovery_records")?;
    }
    Ok(())
}

#[test]
fn event_columns_require_their_declared_storage_types() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "key", "deployment")?;
    for (column, value) in [
        (1, Value::Blob(b"key".to_vec())),
        (2, Value::Real(1.5)),
        (3, Value::Blob(vec![b'a'; 64])),
        (4, Value::Blob(vec![b'0'; 64])),
        (5, Value::Blob(vec![b'b'; 64])),
        (6, Value::Real(1.5)),
    ] {
        let mut values = event_values();
        values[column] = value;
        assert_check(
            connection.execute(
                "INSERT INTO admission_operation_recovery_events VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params_from_iter(values),
            ),
            "recovery_event_storage",
        );
        empty_count(&connection, "admission_operation_recovery_events")?;
    }
    Ok(())
}

#[test]
fn record_identities_refuse_embedded_nul() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    for column in [0, 6] {
        let mut values = record_values();
        values[column] = Value::Text("prefix\0suffix".to_owned());
        assert_check(
            connection.execute(
                "INSERT INTO admission_operation_recovery_records VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params_from_iter(values),
            ),
            "recovery_record_text",
        );
        empty_count(&connection, "admission_operation_recovery_records")?;
    }
    Ok(())
}

#[test]
fn event_identity_bounds_hold_without_foreign_key_enforcement() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    connection.execute_batch(RECORDS)?;
    for (key, constraint) in [
        ("prefix\0suffix".to_owned(), "recovery_event_text"),
        ("k".repeat(513), "length(record_key) BETWEEN 1 AND 512"),
    ] {
        let mut values = event_values();
        values[1] = Value::Text(key);
        assert_check(
            connection.execute(
                "INSERT INTO admission_operation_recovery_events VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params_from_iter(values),
            ),
            constraint,
        );
        empty_count(&connection, "admission_operation_recovery_events")?;
    }
    Ok(())
}

#[test]
fn maximum_multibyte_identities_fit_the_character_bounds() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    connection.execute_batch(RECORDS)?;
    let key = "😀".repeat(512);
    let request = "😀".repeat(256);
    connection.execute(
        "INSERT INTO admission_operation_recovery_records VALUES (?1,?2,'workflow',1,?3,?4,?5)",
        params![
            key,
            "a".repeat(64),
            b"{}".as_slice(),
            "b".repeat(64),
            request
        ],
    )?;
    connection.execute(
        "INSERT INTO admission_operation_recovery_events VALUES (1,?1,1,?2,?3,?4,1)",
        params![key, "a".repeat(64), "0".repeat(64), "b".repeat(64)],
    )?;
    let actual: (String, String) = connection.query_row(
        "SELECT record_key, native_request FROM admission_operation_recovery_records",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(actual, (key, request));
    Ok(())
}
