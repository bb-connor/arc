use std::sync::{Arc, Barrier};

use chio_settle::{ApprovalReplayOutcome, ApprovalReplayStore};
use chio_settle_types::SettlementError;
use chio_store_sqlite::{
    SchemaVersionError, SqliteApprovalReplayStore, SqliteApprovalReplayStoreError,
};
use chio_test_support::prelude::*;

const HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn owned_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().test_unwrap()
}

#[cfg(unix)]
#[test]
fn group_writable_parent_is_refused_before_creating_a_database() {
    use std::os::unix::fs::PermissionsExt;
    let directory = owned_directory();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770))
        .test_unwrap();
    let path = directory.path().join("approvals.db");
    assert!(matches!(
        SqliteApprovalReplayStore::open(&path),
        Err(SqliteApprovalReplayStoreError::InvalidPath)
    ));
    assert!(!path.exists());
}

#[test]
fn a_consumed_approval_remains_spent_after_reopen() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    let store = SqliteApprovalReplayStore::open(&path).test_unwrap();
    assert_eq!(
        store
            .record_if_fresh("request", HASH, 200_000, 100_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Fresh
    );
    drop(store);
    let reopened = SqliteApprovalReplayStore::open(&path).test_unwrap();
    assert_eq!(
        reopened
            .record_if_fresh("request", HASH, 200_000, 101_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Replayed
    );
}

#[test]
fn concurrent_handles_have_exactly_one_fresh_issuance() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    drop(SqliteApprovalReplayStore::open(&path).test_unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = SqliteApprovalReplayStore::open(&path).test_unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .record_if_fresh("request", HASH, 200_000, 100_000)
                    .test_unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|thread| thread.join().test_unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ApprovalReplayOutcome::Fresh)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ApprovalReplayOutcome::Replayed)
            .count(),
        7
    );
}

#[test]
fn collection_cannot_resurrect_an_approval_after_clock_rollback_and_reopen() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    let store = SqliteApprovalReplayStore::open(&path).test_unwrap();
    assert_eq!(
        store
            .record_if_fresh("old", HASH, 200_000, 100_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Fresh
    );
    assert_eq!(
        store
            .record_if_fresh("new", HASH, 400_000, 250_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Fresh
    );
    drop(store);
    let store = SqliteApprovalReplayStore::open(&path).test_unwrap();
    assert!(
        matches!(store.record_if_fresh("old", HASH, 200_000, 150_000), Err(SettlementError::Verification(reason)) if reason == "urn:chio:error:kernel:clock-wall-clock-regression")
    );
    assert_eq!(
        store
            .record_if_fresh("new", HASH, 400_000, 250_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Replayed
    );
}

#[test]
fn capacity_is_persistent_and_only_expired_entries_release_it() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    let store = SqliteApprovalReplayStore::open_with_capacity(&path, 1).test_unwrap();
    assert_eq!(
        store
            .record_if_fresh("first", HASH, 200_000, 100_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Fresh
    );
    assert!(
        matches!(store.record_if_fresh("second", HASH, 300_000, 100_000), Err(SettlementError::Verification(reason)) if reason == "settlement replay capacity exhausted")
    );
    assert_eq!(
        store
            .record_if_fresh("second", HASH, 300_000, 200_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Fresh
    );
    drop(store);
    assert!(matches!(
        SqliteApprovalReplayStore::open_with_capacity(&path, 2),
        Err(SqliteApprovalReplayStoreError::CapacityMismatch)
    ));
}

#[test]
fn an_unstamped_database_is_not_adopted() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection
        .execute_batch("CREATE TABLE retained(value TEXT); INSERT INTO retained VALUES ('keep');")
        .test_unwrap();
    assert!(matches!(
        SqliteApprovalReplayStore::open(&path),
        Err(SqliteApprovalReplayStoreError::Schema(
            SchemaVersionError::ForeignDatabase { found: 0, .. }
        ))
    ));
    let count: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(count, 1);
    let value: String = connection
        .query_row("SELECT value FROM retained", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(value, "keep");
}

#[test]
fn additional_schema_objects_are_refused_without_consuming() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    let store = SqliteApprovalReplayStore::open(&path).test_unwrap();
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection
        .execute_batch("CREATE TABLE unexpected(value TEXT);")
        .test_unwrap();
    assert!(matches!(
        SqliteApprovalReplayStore::open(&path),
        Err(SqliteApprovalReplayStoreError::Schema(
            SchemaVersionError::CatalogMismatch
        ))
    ));
    assert!(
        matches!(store.record_if_fresh("request", HASH, 200_000, 100_000), Err(SettlementError::Verification(reason)) if reason == "settlement replay schema refused")
    );
    connection
        .execute_batch("DROP TABLE unexpected;")
        .test_unwrap();
    assert_eq!(
        store
            .record_if_fresh("request", HASH, 200_000, 100_000)
            .test_unwrap(),
        ApprovalReplayOutcome::Fresh
    );
}

#[test]
fn nondurable_paths_are_refused() {
    for path in ["", ":memory:", "file:approvals.db?mode=memory"] {
        assert!(matches!(
            SqliteApprovalReplayStore::open(path),
            Err(SqliteApprovalReplayStoreError::InvalidPath)
        ));
    }
}

#[cfg(unix)]
#[test]
fn aliased_or_replaced_files_cannot_issue_approvals() {
    let directory = owned_directory();
    let path = directory.path().join("approvals.db");
    let store = SqliteApprovalReplayStore::open(&path).test_unwrap();
    let alias = directory.path().join("alias.db");
    std::os::unix::fs::symlink(&path, &alias).test_unwrap();
    assert!(matches!(
        SqliteApprovalReplayStore::open(&alias),
        Err(SqliteApprovalReplayStoreError::InvalidPath)
    ));
    std::fs::rename(&path, directory.path().join("retained.db")).test_unwrap();
    drop(rusqlite::Connection::open(&path).test_unwrap());
    assert!(
        matches!(store.record_if_fresh("request", HASH, 200_000, 100_000), Err(SettlementError::Verification(reason)) if reason == "settlement replay file identity changed")
    );
}
