use super::*;

fn protected_connection() -> rusqlite::Result<Connection> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = OFF;")?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "owner", "workflow")?;
    record(&connection, "candidate", "workflow")?;
    connection.execute(
        "UPDATE admission_operation_recovery_records
         SET native_namespace = ?1, native_request = 'request', version = 2
         WHERE record_key = 'owner'",
        ["c".repeat(64)],
    )?;
    Ok(connection)
}

pub(super) fn record_snapshot(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    connection
        .prepare(
            "SELECT quote(record_key) || ':' || quote(scope_key) || ':' || quote(kind)
                 || ':' || version || ':' || hex(payload) || ':' || quote(native_namespace)
                 || ':' || quote(native_request)
             FROM admission_operation_recovery_records ORDER BY record_key",
        )?
        .query_map([], |row| row.get(0))?
        .collect()
}

pub(super) fn event_snapshot(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    connection
        .prepare(
            "SELECT sequence || ':' || quote(record_key) || ':' || record_version
                 || ':' || record_digest || ':' || previous_digest || ':' || event_digest
                 || ':' || observed_at
             FROM admission_operation_recovery_events ORDER BY sequence",
        )?
        .query_map([], |row| row.get(0))?
        .collect()
}

#[test]
fn record_key_conflicts_cannot_replace_owned_records() -> rusqlite::Result<()> {
    let connection = protected_connection()?;
    let before = record_snapshot(&connection)?;
    for verb in ["INSERT OR REPLACE", "REPLACE"] {
        let sql = format!(
            "{verb} INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES ('owner', ?1, 'deployment', 1, ?2)"
        );
        assert_trigger_refusal(
            connection.execute(&sql, params!["a".repeat(64), b"{}".as_slice()]),
            "recovery ownership cannot be replaced",
        );
        assert_eq!(record_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn inserts_cannot_replace_a_native_identity_owner() -> rusqlite::Result<()> {
    let connection = protected_connection()?;
    let before = record_snapshot(&connection)?;
    assert_trigger_refusal(
        connection.execute(
            "INSERT OR REPLACE INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload, native_namespace, native_request)
             VALUES ('third', ?1, 'workflow', 1, ?2, ?3, 'request')",
            params!["a".repeat(64), b"{}".as_slice(), "c".repeat(64)],
        ),
        "recovery ownership cannot be replaced",
    );
    assert_eq!(record_snapshot(&connection)?, before);
    Ok(())
}

#[test]
fn updates_cannot_replace_a_native_identity_owner() -> rusqlite::Result<()> {
    let connection = protected_connection()?;
    let before = record_snapshot(&connection)?;
    assert_trigger_refusal(
        connection.execute(
            "UPDATE OR REPLACE admission_operation_recovery_records
             SET native_namespace = ?1, native_request = 'request', version = 2
             WHERE record_key = 'candidate'",
            ["c".repeat(64)],
        ),
        "recovery native identity already has an owner",
    );
    assert_eq!(record_snapshot(&connection)?, before);
    Ok(())
}

#[test]
fn hidden_row_identifiers_cannot_replace_owned_records() -> rusqlite::Result<()> {
    let connection = protected_connection()?;
    let before = record_snapshot(&connection)?;
    for alias in ["rowid", "_rowid_", "oid"] {
        let insert = format!(
            "INSERT OR REPLACE INTO admission_operation_recovery_records
             ({alias}, record_key, scope_key, kind, version, payload)
             VALUES (1, 'third', ?1, 'deployment', 1, ?2)"
        );
        assert_sqlite_error(
            connection.execute(&insert, params!["a".repeat(64), b"{}".as_slice()]),
            ErrorCode::Unknown,
            rusqlite::ffi::SQLITE_ERROR,
            &format!("table admission_operation_recovery_records has no column named {alias}"),
        );
        let update = format!(
            "UPDATE OR REPLACE admission_operation_recovery_records
             SET {alias} = 1, version = 2 WHERE record_key = 'candidate'"
        );
        assert_sqlite_error(
            connection.execute(&update, []),
            ErrorCode::Unknown,
            rusqlite::ffi::SQLITE_ERROR,
            &format!("no such column: {alias}"),
        );
        assert_eq!(record_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn event_sequence_and_record_version_conflicts_cannot_replace_history() -> rusqlite::Result<()> {
    let connection = protected_connection()?;
    connection.execute(
        "INSERT INTO admission_operation_recovery_events
         (sequence, record_key, record_version, record_digest, previous_digest, event_digest, observed_at)
         VALUES (1, 'owner', 2, ?1, ?2, ?3, 1)",
        params!["a".repeat(64), "0".repeat(64), "b".repeat(64)],
    )?;
    let before = event_snapshot(&connection)?;
    for (sequence, version) in [(1, 3), (2, 2)] {
        assert_trigger_refusal(
            connection.execute(
                "INSERT OR REPLACE INTO admission_operation_recovery_events
                 (sequence, record_key, record_version, record_digest, previous_digest, event_digest, observed_at)
                 VALUES (?1, 'owner', ?2, ?3, ?4, ?5, 2)",
                params![sequence, version, "d".repeat(64), "0".repeat(64), "e".repeat(64)],
            ),
            "recovery history cannot be replaced",
        );
        assert_eq!(event_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn record_updates_do_not_use_insert_conflict_resolution() -> rusqlite::Result<()> {
    let connection = protected_connection()?;
    let before = record_snapshot(&connection)?;
    assert_trigger_refusal(
        connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES ('candidate', ?1, 'workflow', 2, ?2)
             ON CONFLICT(record_key) DO UPDATE
             SET version = excluded.version, payload = excluded.payload",
            params!["a".repeat(64), b"{}".as_slice()],
        ),
        "recovery ownership cannot be replaced",
    );
    assert_eq!(record_snapshot(&connection)?, before);
    assert_eq!(
        connection.execute(
            "UPDATE admission_operation_recovery_records
             SET version = 2 WHERE record_key = 'candidate' AND version = 1",
            [],
        )?,
        1
    );
    Ok(())
}
