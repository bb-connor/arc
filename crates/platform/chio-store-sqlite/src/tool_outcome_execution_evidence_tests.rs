use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn seed_schema_parents(connection: &Connection) -> TestResult {
    // These tests isolate SQL constraints. Native integration tests separately
    // qualify canonical records, real serving history and anchored participants.
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE chio_serving_leases (
             store_uuid TEXT, owner_epoch INTEGER, lease_id TEXT, end_head_index INTEGER,
             PRIMARY KEY (store_uuid, owner_epoch)
         );
         INSERT INTO chio_serving_leases VALUES ('store', 1, 'lease', NULL);
         CREATE TABLE admission_operations (operation_id TEXT PRIMARY KEY, terminal INTEGER);
         INSERT INTO admission_operations VALUES ('operation', 0);",
    )?;
    connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
    let digest = "a".repeat(64);
    connection.execute(
        "INSERT INTO tool_outcome_blobs VALUES (?1, 1, X'00', 1, 'store', 'lease', 1)",
        [&digest],
    )?;
    connection.execute(
        "INSERT INTO tool_outcomes VALUES ('operation', ?1, 'request', ?1, 1, ?1, ?1, X'00', 1, 1, 'store', 'lease', 1)",
        [&digest],
    )?;
    Ok(())
}

fn predecessor() -> TestResult<Connection> {
    let connection = Connection::open_in_memory()?;
    crate::check_schema_version(
        &connection,
        TOOL_OUTCOME_SCHEMA_KEY,
        3,
        TOOL_OUTCOME_SCHEMA_ANCHORS,
    )?;
    connection.execute_batch(TOOL_OUTCOME_SCHEMA)?;
    connection.execute_batch(SECURITY_RELEASE_SCHEMA)?;
    crate::stamp_schema_version(&connection, TOOL_OUTCOME_SCHEMA_KEY, 3)?;
    Ok(connection)
}

fn version(connection: &Connection) -> TestResult<i32> {
    Ok(connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn exact_v3_migration_preserves_release_schema_and_creates_empty_execution_projection() -> TestResult
{
    let mut connection = predecessor()?;
    let before = tool_outcome_schema_catalog(&connection)?;
    initialize_tool_outcome_schema(&mut connection)?;
    assert_eq!(version(&connection)?, 4);
    let after = tool_outcome_schema_catalog(&connection)?;
    assert!(before.iter().all(|entry| after.contains(entry)));
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM tool_outcome_execution_evidence",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    initialize_tool_outcome_schema(&mut connection)?;
    Ok(())
}

#[test]
fn v3_predecessor_check_accepts_existing_release_rows_without_rewriting_them() -> TestResult {
    let connection = predecessor()?;
    // The predecessor gate must preserve existing release records. Full opening
    // subsequently validates their canonical contents and participant binding.
    seed_schema_parents(&connection)?;
    connection.execute(
        "INSERT INTO tool_outcome_security_releases VALUES ('operation', ?1, ?2, 1, 'store', 'lease', 1)",
        params![b"retained-release".as_slice(), "a".repeat(64)],
    )?;
    verify_pre_migration(&connection, 3)?;
    assert_eq!(
        connection.query_row(
            "SELECT canonical_record FROM tool_outcome_security_releases",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        b"retained-release"
    );
    Ok(())
}

#[test]
fn v3_migration_rejects_partial_weakened_and_future_execution_namespaces_atomically() -> TestResult
{
    for sql in [
        "DROP TRIGGER tool_outcome_security_releases_no_delete",
        "DROP TRIGGER tool_outcome_security_releases_no_update; CREATE TRIGGER tool_outcome_security_releases_no_update BEFORE UPDATE ON tool_outcome_security_releases BEGIN SELECT 1; END",
        "CREATE TABLE tool_outcome_execution_evidence(fake TEXT)",
        "CREATE VIEW TOOL_OUTCOME_EXECUTION_EVIDENCE AS SELECT 1",
        "CREATE TABLE tool_outcome_execution_evidence_future(fake TEXT)",
    ] {
        let mut connection = predecessor()?;
        connection.execute_batch(sql)?;
        let before = tool_outcome_schema_catalog(&connection)?;
        assert!(initialize_tool_outcome_schema(&mut connection).is_err(), "accepted {sql}");
        assert_eq!(version(&connection)?, 3);
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    }
    Ok(())
}

#[test]
fn unstamped_execution_namespace_and_future_schema_are_not_adopted() -> TestResult {
    let mut unstamped = Connection::open_in_memory()?;
    unstamped.execute_batch("CREATE TABLE TOOL_OUTCOME_EXECUTION_EVIDENCE(fake TEXT)")?;
    assert!(initialize_tool_outcome_schema(&mut unstamped).is_err());
    assert_eq!(
        unstamped.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    let mut future = predecessor()?;
    crate::stamp_schema_version(&future, TOOL_OUTCOME_SCHEMA_KEY, 5)?;
    assert!(initialize_tool_outcome_schema(&mut future).is_err());
    assert_eq!(version(&future)?, 5);
    Ok(())
}

#[test]
fn current_schema_rejects_missing_or_weakened_execution_guards_without_repair() -> TestResult {
    for sql in [
        "DROP TRIGGER tool_outcome_execution_evidence_no_delete",
        "DROP TRIGGER tool_outcome_execution_evidence_no_update; CREATE TRIGGER tool_outcome_execution_evidence_no_update BEFORE UPDATE ON tool_outcome_execution_evidence BEGIN SELECT 1; END",
        "DROP TABLE tool_outcome_execution_evidence",
    ] {
        let mut connection = predecessor()?;
        initialize_tool_outcome_schema(&mut connection)?;
        connection.execute_batch(sql)?;
        let before = tool_outcome_schema_catalog(&connection)?;
        assert!(initialize_tool_outcome_schema(&mut connection).is_err());
        assert_eq!(version(&connection)?, 4);
        assert_eq!(tool_outcome_schema_catalog(&connection)?, before);
    }
    Ok(())
}

#[test]
fn execution_schema_prevents_replacement_mutation_deletion_and_wrong_owner() -> TestResult {
    let connection = Connection::open_in_memory()?;
    seed_schema_parents(&connection)?;
    connection.execute_batch(EXECUTION_EVIDENCE_SCHEMA)?;
    let insert = "INSERT INTO tool_outcome_execution_evidence VALUES ('operation', ?1, ?2, 1, 'store', ?3, 1)";
    assert!(connection
        .execute(
            insert,
            params![b"record".as_slice(), "a".repeat(64), "wrong"]
        )
        .is_err());
    connection.execute(
        insert,
        params![b"record".as_slice(), "a".repeat(64), "lease"],
    )?;
    for sql in [
        "UPDATE tool_outcome_execution_evidence SET canonical_record = X'00'",
        "DELETE FROM tool_outcome_execution_evidence",
        "INSERT OR REPLACE INTO tool_outcome_execution_evidence SELECT * FROM tool_outcome_execution_evidence",
    ] {
        assert!(connection.execute(sql, []).is_err(), "accepted {sql}");
    }
    assert_eq!(
        connection.query_row(
            "SELECT canonical_record FROM tool_outcome_execution_evidence",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        b"record"
    );
    Ok(())
}

#[test]
fn execution_load_rejects_oversized_blob_before_decoding() -> TestResult {
    let connection = Connection::open_in_memory()?;
    // Deliberately bypass the production schema to model corrupt storage. The
    // loader must apply its own SQL bound before copying this BLOB into Rust.
    connection.execute_batch(
        "CREATE TABLE tool_outcome_execution_evidence (
        operation_id TEXT, canonical_record BLOB, participant_digest TEXT,
        recorded_at_unix_ms INTEGER, store_uuid TEXT, store_lease_id TEXT,
        store_owner_epoch INTEGER
    )",
    )?;
    connection.execute(
        "INSERT INTO tool_outcome_execution_evidence VALUES ('operation', zeroblob(1048577), ?1, 1, 'store', 'lease', 1)",
        ["a".repeat(64)],
    )?;
    let error = load(&connection, "operation")
        .err()
        .ok_or("oversized record was accepted")?;
    assert!(error.to_string().contains("exceeds its bounds"));
    Ok(())
}
