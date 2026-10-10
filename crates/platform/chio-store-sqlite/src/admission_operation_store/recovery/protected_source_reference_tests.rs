//! Exact reader tests; native owner adoption and full chain custody are separate.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: &str = "knowledge-influence:authenticated-source-head";

fn connection() -> Result<Connection, Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(super::super::super::SQL)?;
    connection.execute_batch(
        "CREATE TABLE authority_global_commits (
            commit_sequence INTEGER PRIMARY KEY,
            projection_kind TEXT NOT NULL,
            projection_key TEXT NOT NULL,
            projection_sequence INTEGER NOT NULL,
            projection_reference_digest TEXT NOT NULL
        );
        CREATE INDEX authority_global_commits_projection ON authority_global_commits
            (projection_kind,projection_key,projection_sequence);",
    )?;
    Ok(connection)
}

fn append_head(connection: &Connection, version: u64) -> TestResult {
    let scope = "1".repeat(64);
    let payload = encode(&serde_json::json!({"revision":version}))?;
    let digest = record_digest(KEY, &scope, "command", version, &payload, None, None)?;
    let previous: String = if version == 1 {
        "0".repeat(64)
    } else {
        connection.query_row(
            "SELECT event_digest FROM admission_operation_recovery_events WHERE sequence=?1",
            [i64::try_from(version - 1)?],
            |row| row.get(0),
        )?
    };
    let event = event_digest(version, KEY, version, &digest, &previous, version)?;
    if version == 1 {
        connection.execute(
            "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
             VALUES(?1,?2,'command',1,?3)", params![KEY,scope,payload],
        )?;
    } else {
        connection.execute(
            "UPDATE admission_operation_recovery_records SET version=?2,payload=?3 WHERE record_key=?1",
            params![KEY,i64::try_from(version)?,payload],
        )?;
    }
    connection.execute(
        "INSERT INTO admission_operation_recovery_events
         (sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at)
         VALUES(?1,?2,?1,?3,?4,?5,?1)",
        params![i64::try_from(version)?, KEY, digest, previous, event],
    )?;
    connection.execute(
        "INSERT INTO authority_global_commits
         (commit_sequence,projection_kind,projection_key,projection_sequence,projection_reference_digest)
         VALUES(?1,'recovery',?2,?1,?3)", params![i64::try_from(version)?,KEY,event],
    )?;
    Ok(())
}

#[test]
fn authenticated_current_source_head_is_read_only() -> TestResult {
    let connection = connection()?;
    append_head(&connection, 1)?;
    append_head(&connection, 2)?;
    let before = connection.total_changes();
    let reference = source_reference(&connection, KEY)?;
    assert_eq!(reference.record_key(), KEY);
    assert_eq!(reference.scope_key(), "1".repeat(64));
    assert_eq!(reference.kind(), "command");
    assert_eq!(reference.version(), 2);
    assert_eq!(reference.event_sequence(), 2);
    assert_eq!(reference.global_commit_sequence(), 2);
    assert_ne!(reference.digest(), &ProjectionDigest::from_bytes([0; 32]));
    verify_source_reference(&connection, &reference)?;
    assert_eq!(connection.total_changes(), before);
    Ok(())
}

#[test]
fn authentic_old_projection_cannot_mint_current_source() -> TestResult {
    let connection = connection()?;
    append_head(&connection, 1)?;
    let old: Vec<u8> = connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [KEY],
        |row| row.get(0),
    )?;
    append_head(&connection, 2)?;
    // Deliberately damaged reader fixture, not a normal serving-owner mutation.
    connection.execute_batch("DROP TRIGGER admission_operation_recovery_identity")?;
    connection.execute(
        "UPDATE admission_operation_recovery_records SET version=1,payload=?2 WHERE record_key=?1",
        params![KEY, old],
    )?;
    assert_eq!(
        raw_checked(&connection, KEY)?
            .ok_or("old row absent")?
            .version,
        1
    );
    let before = connection.total_changes();
    assert!(
        matches!(
            source_reference(&connection, KEY),
            Err(AdmissionOperationStoreError::Invariant(_))
        ),
        "a prior authentic projection became a current progress or retirement source"
    );
    assert_eq!(connection.total_changes(), before);
    Ok(())
}

#[test]
fn newer_global_reference_cannot_leave_a_current_source_head() -> TestResult {
    let connection = connection()?;
    append_head(&connection, 1)?;
    connection.execute(
        "INSERT INTO authority_global_commits
         (commit_sequence,projection_kind,projection_key,projection_sequence,projection_reference_digest)
         VALUES(2,'recovery',?1,2,?2)", params![KEY,"2".repeat(64)],
    )?;
    let before = connection.total_changes();
    assert!(
        matches!(
            source_reference(&connection, KEY),
            Err(AdmissionOperationStoreError::Invariant(_))
        ),
        "current source ignored a retained newer global ownership reference"
    );
    assert_eq!(connection.total_changes(), before);
    Ok(())
}
