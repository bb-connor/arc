//! Recovery of the caller execution ledger's connection after a panic inside a
//! critical section. Nothing outside the database records a commit (the path
//! identity is verified before every write and the directory is synced only
//! at provisioning), so there is no phase between a commit and an anchor
//! write.
//!
//! The ledger's one public operation, `execute_once`, needs a dispatch
//! authorization signed by a kernel that committed the admission, which no
//! fixture in this crate can produce. These tests therefore drive the store
//! at its connection boundary: the lock the operations take, and the
//! per-operation guard (`validate_live`) they run first.

use std::path::Path;

use chio_core::crypto::Keypair;
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::caller_delivery::CallerExecutorIdentityV1;
use rusqlite::{Connection, Transaction};
use tempfile::TempDir;

use super::SqliteCallerExecutionLedger;
use crate::store_connection::test_support::{
    fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
    recovery_events_during,
};
use crate::store_connection::FenceReason;

fn provisioned() -> (TempDir, SqliteCallerExecutionLedger) {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "executor-under-recovery")
            .expect("executor id"),
        public_key: Keypair::generate().public_key(),
        key_epoch: 1,
    };
    let ledger = SqliteCallerExecutionLedger::provision(&database(&directory), executor, 4)
        .expect("provision the ledger");
    (directory, ledger)
}

fn database(directory: &TempDir) -> std::path::PathBuf {
    directory.path().join("executor.db")
}

/// The executor clock is the ledger's smallest real durable write; its
/// trigger allows it only to advance.
fn advance_clock(transaction: &Transaction<'_>) {
    transaction
        .execute(
            "UPDATE caller_executor_clock SET high_water_unix_ms = high_water_unix_ms + 1 WHERE singleton = 1",
            [],
        )
        .expect("advance the executor clock");
}

fn durable_clock(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open a reader")
        .query_row(
            "SELECT high_water_unix_ms FROM caller_executor_clock WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read the executor clock")
}

/// The guard every ledger operation runs first, on the lock it takes.
fn read(ledger: &SqliteCallerExecutionLedger) -> Result<(), String> {
    let connection = ledger
        .connection
        .lock()
        .map_err(|fenced| fenced.to_string())?;
    ledger
        .validate_live(&connection)
        .map_err(|error| error.to_string())
}

#[test]
fn the_ledger_pairs_no_artifact_with_a_commit() {
    let (_directory, ledger) = provisioned();
    assert!(!ledger.connection.is_anchored());
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_ledger_serves() {
    let (directory, ledger) = provisioned();
    let clock = durable_clock(&database(&directory));
    panic_before_commit(&ledger.connection, advance_clock);

    let (result, events) = recovery_events_during(|| read(&ledger));
    result.expect("the ledger serves after a verified rollback");
    assert_eq!(events, [recovered("caller_execution_ledger")]);
    assert_eq!(durable_clock(&database(&directory)), clock);
}

#[test]
fn a_denied_rollback_fences_the_ledger() {
    let (directory, ledger) = provisioned();
    let clock = durable_clock(&database(&directory));
    panic_with_rollback_denied(&ledger.connection, advance_clock);

    let (result, events) = recovery_events_during(|| read(&ledger));
    let fence = ledger.connection.fence().expect("the connection is fenced");
    assert!(matches!(fence.reason, FenceReason::RollbackFailed(_)));
    assert_eq!(result, Err(fence.to_string()));
    assert_eq!(events, [fenced("caller_execution_ledger")]);
    assert_eq!(
        durable_clock(&database(&directory)),
        clock,
        "the uncommitted write is never read"
    );
}

#[test]
fn a_panic_after_commit_recovers_with_the_write_visible() {
    let (directory, ledger) = provisioned();
    let clock = durable_clock(&database(&directory));
    panic_after_commit(&ledger.connection, advance_clock, |_| {});

    let (result, events) = recovery_events_during(|| read(&ledger));
    result.expect("the ledger serves the committed write");
    assert_eq!(events, [recovered("caller_execution_ledger")]);
    assert_eq!(durable_clock(&database(&directory)), clock + 1);
}
