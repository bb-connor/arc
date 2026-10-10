//! Exact-key reader corruption fixtures do not qualify live serving-owner adoption.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn connection() -> Result<Connection, Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    // Missing projection corruption is deliberate. Normal owned writers retain
    // rows and FK/no-delete protections; this fixture exercises reader absence.
    connection.execute_batch("PRAGMA foreign_keys=OFF")?;
    connection.execute_batch(super::super::SQL)?;
    // Only the exact immutable-reference columns are needed by this reader unit.
    // Full chain authentication is covered by serving-owner/native regressions.
    connection.execute_batch("CREATE TABLE authority_global_commits (
        projection_kind TEXT NOT NULL, projection_key TEXT NOT NULL
    ); CREATE INDEX global_projection_reference ON authority_global_commits(projection_kind,projection_key)")?;
    Ok(connection)
}

fn retain_event_reference(connection: &Connection, key: &str) -> TestResult {
    let zero = "0".repeat(64);
    connection.execute(
        "INSERT INTO admission_operation_recovery_events(sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at)
         VALUES(1,?1,1,?2,?2,?2,1)", params![key,zero],
    )?;
    Ok(())
}

#[test]
fn missing_event_projection_never_becomes_pristine() -> TestResult {
    let connection = connection()?;
    let key = "knowledge-reference:missing-source";
    retain_event_reference(&connection, key)?;
    assert!(
        matches!(
            raw_checked(&connection, key),
            Err(AdmissionOperationStoreError::Invariant(_))
        ),
        "retained event ownership was treated as a pristine missing allocation"
    );
    Ok(())
}

#[test]
fn missing_global_projection_never_becomes_pristine() -> TestResult {
    let connection = connection()?;
    let key = "knowledge-influence:missing-fold";
    connection.execute("INSERT INTO authority_global_commits(projection_kind,projection_key) VALUES('recovery',?1)",[key])?;
    assert!(
        matches!(
            raw_checked(&connection, key),
            Err(AdmissionOperationStoreError::Invariant(_))
        ),
        "retained global ownership was treated as a pristine missing allocation"
    );
    Ok(())
}

#[test]
fn unrelated_history_does_not_block_pristine_projection() -> TestResult {
    let connection = connection()?;
    let key = "knowledge-reference:never-created";
    assert!(raw_checked(&connection, key)?.is_none());
    retain_event_reference(&connection, "knowledge-reference:other-owner")?;
    connection.execute("INSERT INTO authority_global_commits(projection_kind,projection_key) VALUES('recovery','knowledge-influence:other-fold')",[])?;
    assert!(raw_checked(&connection, key)?.is_none());
    let (events, globals): (i64,i64) = connection.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events),(SELECT count(*) FROM authority_global_commits)",
        [],|row|Ok((row.get(0)?,row.get(1)?)),
    )?;
    assert_eq!((events, globals), (1, 1));
    Ok(())
}
