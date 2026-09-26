//! Recovery of the standalone admission operation store's connection after a
//! panic inside a critical section. Nothing outside the database records a
//! commit here, so there is no phase between a commit and an anchor write;
//! the phases that exist are before commit, a refused rollback, and after
//! commit before the caller's acknowledgement.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_kernel::{AdmissionOperationError, AdmissionOperationStore};
use rusqlite::Connection;
use tempfile::TempDir;

use super::SqliteAdmissionOperationStore;
use crate::store_connection::test_support::{
    fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
    recovery_events_during, user_version, write_probe_user_version, PROBE_USER_VERSION,
};
use crate::store_connection::FenceReason;

fn open() -> (TempDir, SqliteAdmissionOperationStore) {
    let directory = tempfile::tempdir().expect("tempdir");
    let store =
        SqliteAdmissionOperationStore::open(directory.path().join("admission.db")).expect("open");
    (directory, store)
}

fn read(store: &SqliteAdmissionOperationStore) -> Result<(), AdmissionOperationError> {
    store.load("operation").map(drop)
}

fn durable_user_version(directory: &TempDir) -> i64 {
    user_version(&Connection::open(directory.path().join("admission.db")).expect("open a reader"))
}

#[test]
fn the_store_pairs_no_artifact_with_a_commit() {
    let (_directory, store) = open();
    assert!(!store.connection.is_anchored());
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_store_serves() {
    let (directory, store) = open();
    panic_before_commit(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the store serves after a verified rollback");
    assert_eq!(events, [recovered("admission_operation")]);
    assert_eq!(durable_user_version(&directory), 0);
}

#[test]
fn a_denied_rollback_fences_the_store() {
    let (directory, store) = open();
    panic_with_rollback_denied(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read(&store));
    let fence = store.connection.fence().expect("the connection is fenced");
    assert!(matches!(fence.reason, FenceReason::RollbackFailed(_)));
    assert!(
        matches!(result, Err(AdmissionOperationError::Unavailable(ref detail)) if *detail == fence.to_string()),
        "{result:?}"
    );
    assert_eq!(events, [fenced("admission_operation")]);
    assert_eq!(
        durable_user_version(&directory),
        0,
        "the uncommitted write is never read"
    );
}

#[test]
fn a_panic_after_commit_recovers_with_the_write_visible() {
    let (directory, store) = open();
    panic_after_commit(&store.connection, write_probe_user_version, |_| {});

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the store serves the committed write");
    assert_eq!(events, [recovered("admission_operation")]);
    assert_eq!(durable_user_version(&directory), PROBE_USER_VERSION);
}
