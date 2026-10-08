//! A storage failure while reading approval migration records is an outage,
//! distinct from a retained record that fails its integrity checks.

use super::*;
use crate::admission_operation_store::governed_approval_replay::verify_all_records;

#[test]
fn a_locked_store_is_unavailable_rather_than_corrupt_approval_migration_history(
) -> AnchoredTestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval-records.db");
    let holder = Connection::open(&path)?;
    holder.execute_batch("CREATE TABLE unrelated (id INTEGER); BEGIN EXCLUSIVE;")?;
    let reader = Connection::open(&path)?;
    reader.busy_timeout(std::time::Duration::ZERO)?;

    let error = verify_all_records(&reader)
        .err()
        .ok_or("a locked store cannot be verified")?;
    assert!(
        matches!(error, RecordIntegrityError::Storage(_)),
        "{error:?}"
    );
    assert!(
        matches!(
            AdmissionOperationStoreError::from(error),
            AdmissionOperationStoreError::Unavailable(_)
        ),
        "a busy store must stay retryable"
    );
    holder.execute_batch("ROLLBACK;")?;
    Ok(())
}

#[test]
fn a_partial_approval_migration_schema_is_an_integrity_failure() -> AnchoredTestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE governed_approval_replay_migration_expectations (approval_authority_id TEXT);",
    )?;

    let error = verify_all_records(&connection)
        .err()
        .ok_or("a partial migration schema cannot verify")?;
    assert!(
        matches!(
            &error,
            RecordIntegrityError::Invalid(detail)
                if detail == "partial governed approval migration schema"
        ),
        "{error:?}"
    );
    assert_eq!(
        AdmissionOperationStoreError::from(error),
        AdmissionOperationStoreError::Invariant(
            "partial governed approval migration schema".into()
        )
    );
    Ok(())
}

#[test]
fn a_locked_store_keeps_its_sqlite_cause_at_the_approval_authority_boundary() -> AnchoredTestResult
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval-pristine.db");
    let holder = Connection::open(&path)?;
    holder.execute_batch("CREATE TABLE unrelated (id INTEGER); BEGIN EXCLUSIVE;")?;
    let reader = Connection::open(&path)?;
    reader.busy_timeout(std::time::Duration::ZERO)?;

    let error = crate::admission_operation_store::verify_governed_approval_replay_pristine(&reader)
        .err()
        .ok_or("a locked store cannot prove a pristine migration state")?;
    assert!(
        matches!(error, SqliteServingOwnerError::Sqlite(_)),
        "{error:?}"
    );
    holder.execute_batch("ROLLBACK;")?;
    Ok(())
}
