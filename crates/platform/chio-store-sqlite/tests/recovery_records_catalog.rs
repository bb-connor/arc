use rusqlite::{params, Connection, Error, ErrorCode};

#[path = "recovery_records_catalog/bounds.rs"]
mod bounds;

#[path = "recovery_records_catalog/replacement.rs"]
mod replacement;

#[path = "recovery_records_catalog/encodings.rs"]
mod encodings;

#[path = "recovery_records_catalog/malformed_text.rs"]
mod malformed_text;

const RECORDS: &str = include_str!("../src/admission_operation_recovery.sql");
const DEFERRALS: &str = include_str!("../src/admission_operation_store/recovery/schema.sql");

fn assert_sqlite_error<T: std::fmt::Debug>(
    result: rusqlite::Result<T>,
    code: ErrorCode,
    extended_code: i32,
    message: &str,
) {
    match result {
        Err(Error::SqliteFailure(error, Some(actual)))
        | Err(Error::SqlInputError {
            error, msg: actual, ..
        }) => {
            assert_eq!(error.code, code);
            assert_eq!(error.extended_code, extended_code);
            assert_eq!(actual, message);
        }
        other => panic!("expected SQLite refusal {message:?}, got {other:?}"),
    }
}

fn assert_check<T: std::fmt::Debug>(result: rusqlite::Result<T>, constraint: &str) {
    assert_sqlite_error(
        result,
        ErrorCode::ConstraintViolation,
        rusqlite::ffi::SQLITE_CONSTRAINT_CHECK,
        &format!("CHECK constraint failed: {constraint}"),
    );
}

fn assert_trigger_refusal<T: std::fmt::Debug>(result: rusqlite::Result<T>, message: &str) {
    assert_sqlite_error(
        result,
        ErrorCode::ConstraintViolation,
        rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER,
        message,
    );
}

fn record(connection: &Connection, key: &str, kind: &str) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES (?1, ?2, ?3, 1, ?4)",
        params![key, "a".repeat(64), kind, b"{}".as_slice()],
    )?;
    Ok(())
}

#[test]
fn records_and_deferrals_protect_deletion_in_either_installation_order() -> rusqlite::Result<()> {
    for records_first in [true, false] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE admission_operations (operation_id TEXT PRIMARY KEY);
             INSERT INTO admission_operations VALUES ('operation');",
        )?;
        let catalogs = if records_first {
            [RECORDS, DEFERRALS]
        } else {
            [DEFERRALS, RECORDS]
        };
        for catalog in catalogs {
            connection.execute_batch(catalog)?;
        }
        record(&connection, "deployment", "deployment")?;
        connection.execute(
            "INSERT INTO admission_operation_recovery_deferrals
             (operation_id, canonical_status, status_digest, quarantined, retry_not_before_unix_ms)
             VALUES ('operation', ?1, ?2, 1, 1)",
            params![b"{}".as_slice(), "b".repeat(64)],
        )?;
        for (trigger, table) in [
            (
                "admission_operation_recovery_records_no_delete",
                "admission_operation_recovery_records",
            ),
            (
                "admission_operation_recovery_no_delete",
                "admission_operation_recovery_deferrals",
            ),
        ] {
            let owner: String = connection.query_row(
                "SELECT tbl_name FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [trigger],
                |row| row.get(0),
            )?;
            assert_eq!(owner, table);
        }
        assert_trigger_refusal(
            connection.execute("DELETE FROM admission_operation_recovery_records", []),
            "recovery ownership cannot be deleted",
        );
        assert_trigger_refusal(
            connection.execute("DELETE FROM admission_operation_recovery_deferrals", []),
            "recovery history must be retained",
        );
    }
    Ok(())
}

#[test]
fn occupied_record_catalog_is_refused() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    assert_sqlite_error(
        connection.execute_batch(RECORDS),
        ErrorCode::Unknown,
        rusqlite::ffi::SQLITE_ERROR,
        "table admission_operation_recovery_records already exists",
    );
    Ok(())
}

#[test]
fn records_delete_trigger_cannot_be_shadowed_by_another_table() -> rusqlite::Result<()> {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE unrelated (id INTEGER PRIMARY KEY);
         CREATE TRIGGER admission_operation_recovery_records_no_delete
         BEFORE DELETE ON unrelated BEGIN SELECT RAISE(ABORT, 'unrelated deletion'); END;",
    )?;
    {
        let transaction = connection.transaction()?;
        assert_sqlite_error(
            transaction.execute_batch(RECORDS),
            ErrorCode::Unknown,
            rusqlite::ffi::SQLITE_ERROR,
            "trigger admission_operation_recovery_records_no_delete already exists",
        );
        transaction.rollback()?;
    }
    let record_tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema
         WHERE type = 'table' AND name = 'admission_operation_recovery_records'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(record_tables, 0);
    Ok(())
}

#[test]
fn record_identity_and_consecutive_versions_are_enforced() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "deployment", "deployment")?;
    for statement in [
        "UPDATE admission_operation_recovery_records SET record_key = 'other', version = 2",
        "UPDATE admission_operation_recovery_records SET scope_key = hex(zeroblob(32)), version = 2",
        "UPDATE admission_operation_recovery_records SET kind = 'command', version = 2",
        "UPDATE admission_operation_recovery_records SET version = 1",
        "UPDATE admission_operation_recovery_records SET version = 3",
    ] {
        assert_trigger_refusal(
            connection.execute(statement, []),
            "recovery identity is immutable",
        );
    }
    assert_eq!(
        connection.execute(
            "UPDATE admission_operation_recovery_records SET payload = ?1, version = 2",
            [br#"{"updated":true}"#.as_slice()],
        )?,
        1
    );
    Ok(())
}

#[test]
fn bound_native_identity_cannot_be_reassigned_or_removed() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "workflow", "workflow")?;
    connection.execute(
        "UPDATE admission_operation_recovery_records
         SET native_namespace = ?1, native_request = 'request', version = 2",
        ["c".repeat(64)],
    )?;
    for statement in [
        "UPDATE admission_operation_recovery_records SET native_request = 'other', version = 3",
        "UPDATE admission_operation_recovery_records
         SET native_namespace = hex(zeroblob(32)), version = 3",
        "UPDATE admission_operation_recovery_records
         SET native_namespace = NULL, native_request = NULL, version = 3",
    ] {
        assert_trigger_refusal(
            connection.execute(statement, []),
            "recovery identity is immutable",
        );
    }
    Ok(())
}

#[test]
fn native_identity_has_one_record_owner() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "first", "workflow")?;
    record(&connection, "second", "workflow")?;
    connection.execute(
        "UPDATE admission_operation_recovery_records
         SET native_namespace = ?1, native_request = 'request', version = 2
         WHERE record_key = 'first'",
        ["c".repeat(64)],
    )?;
    assert_sqlite_error(
        connection.execute(
            "UPDATE admission_operation_recovery_records
             SET native_namespace = ?1, native_request = 'request', version = 2
             WHERE record_key = 'second'",
            ["c".repeat(64)],
        ),
        ErrorCode::ConstraintViolation,
        rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER,
        "recovery native identity already has an owner",
    );
    Ok(())
}

#[test]
fn recovery_events_cannot_be_changed_or_deleted() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    connection.execute_batch(RECORDS)?;
    record(&connection, "deployment", "deployment")?;
    connection.execute(
        "INSERT INTO admission_operation_recovery_events
         (sequence, record_key, record_version, record_digest, previous_digest, event_digest, observed_at)
         VALUES (1, 'deployment', 1, ?1, ?2, ?3, 1)",
        params!["a".repeat(64), "0".repeat(64), "b".repeat(64)],
    )?;
    assert_trigger_refusal(
        connection.execute(
            "UPDATE admission_operation_recovery_events SET observed_at = 2",
            [],
        ),
        "recovery history is immutable",
    );
    assert_trigger_refusal(
        connection.execute("DELETE FROM admission_operation_recovery_events", []),
        "recovery history cannot be deleted",
    );
    Ok(())
}

#[test]
fn recovery_payload_bounds_are_enforced() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    for length in [0, 262145] {
        assert_sqlite_error(
            connection.execute(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload)
                 VALUES ('record', ?1, 'deployment', 1, ?2)",
                params!["a".repeat(64), vec![b'x'; length]],
            ),
            ErrorCode::ConstraintViolation,
            rusqlite::ffi::SQLITE_CONSTRAINT_CHECK,
            "CHECK constraint failed: length(payload) BETWEEN 1 AND 262144",
        );
    }
    for (key, length) in [("minimum", 1), ("maximum", 262144)] {
        connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES (?1, ?2, 'deployment', 1, ?3)",
            params![key, "a".repeat(64), vec![b'x'; length]],
        )?;
    }
    Ok(())
}

#[test]
fn recovery_record_requires_a_nonnull_identity() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    assert_sqlite_error(
        connection.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES (NULL, ?1, 'deployment', 1, ?2)",
            params!["a".repeat(64), b"{}".as_slice()],
        ),
        ErrorCode::ConstraintViolation,
        rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL,
        "NOT NULL constraint failed: admission_operation_recovery_records.record_key",
    );
    Ok(())
}

#[test]
fn native_identity_requires_a_workflow_record() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    for kind in ["deployment", "command"] {
        assert_sqlite_error(
            connection.execute(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload, native_namespace, native_request)
                 VALUES (?1, ?2, ?1, 1, ?3, ?4, 'request')",
                params![kind, "a".repeat(64), b"{}".as_slice(), "b".repeat(64)],
            ),
            ErrorCode::ConstraintViolation,
            rusqlite::ffi::SQLITE_CONSTRAINT_CHECK,
            "CHECK constraint failed: kind = 'workflow' OR native_request IS NULL",
        );
    }
    Ok(())
}

#[test]
fn native_identity_requires_both_binding_fields() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    let namespace = "b".repeat(64);
    for (namespace, request) in [(Some(namespace.as_str()), None), (None, Some("request"))] {
        assert_sqlite_error(
            connection.execute(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload, native_namespace, native_request)
                 VALUES ('workflow', ?1, 'workflow', 1, ?2, ?3, ?4)",
                params!["a".repeat(64), b"{}".as_slice(), namespace, request],
            ),
            ErrorCode::ConstraintViolation,
            rusqlite::ffi::SQLITE_CONSTRAINT_CHECK,
            "CHECK constraint failed: (native_namespace IS NULL) = (native_request IS NULL)",
        );
    }
    Ok(())
}
