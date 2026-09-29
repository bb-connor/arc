//! Recovery of the two connections a security-state database is served
//! through, the security state store's and the participant source's, after a
//! panic inside a critical section. Neither pairs a commit with anything
//! outside the database: the seal is a row, lifecycle proofs read a lock-path
//! identity before they write, and every mutation is one RAII transaction. So
//! there is no phase between a commit and an anchor write for either.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]

use std::path::PathBuf;

use chio_security_types::ports::{FlowStateStore, PortErrorKind};
use rusqlite::Connection;
use tempfile::TempDir;

use super::{key, seed, Error, SqliteSecurityParticipantSource, SqliteSecurityStateStore};
use crate::store_connection::test_support::{
    fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
    recovery_events_during, user_version, write_probe_user_version, PROBE_USER_VERSION,
};
use crate::store_connection::FenceReason;

fn seeded() -> (TempDir, PathBuf, SqliteSecurityStateStore) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("security.db");
    let store = seed(&path).expect("seed the security state");
    (directory, path, store)
}

fn durable_user_version(path: &PathBuf) -> i64 {
    user_version(&Connection::open(path).expect("open a reader"))
}

fn read_state(store: &SqliteSecurityStateStore) -> Result<(), PortErrorKind> {
    store
        .load(&key().expect("flow state key"))
        .map(drop)
        .map_err(|error| error.kind())
}

fn read_seal(source: &SqliteSecurityParticipantSource) -> Result<(), Error> {
    source.load_seal().map(drop)
}

#[test]
fn neither_connection_pairs_an_artifact_with_a_commit() {
    let (_directory, path, store) = seeded();
    let source = SqliteSecurityParticipantSource::open(&path).expect("open the source");
    assert!(!store.connection.is_anchored());
    assert!(!source.connection.is_anchored());
}

#[test]
fn security_state_panic_before_commit_rolls_back_and_the_store_serves() {
    let (_directory, path, store) = seeded();
    panic_before_commit(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read_state(&store));
    result.expect("the store serves after a verified rollback");
    assert_eq!(events, [recovered("security_state")]);
    assert_eq!(durable_user_version(&path), 0);
}

#[test]
fn security_state_denied_rollback_fences_the_store() {
    let (_directory, path, store) = seeded();
    panic_with_rollback_denied(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read_state(&store));
    let fence = store.connection.fence().expect("the connection is fenced");
    assert!(matches!(fence.reason, FenceReason::RollbackFailed(_)));
    assert_eq!(result, Err(PortErrorKind::Unavailable));
    assert_eq!(events, [fenced("security_state")]);
    assert_eq!(
        durable_user_version(&path),
        0,
        "the uncommitted write is never read"
    );
}

#[test]
fn security_state_panic_after_commit_recovers_with_the_write_visible() {
    let (_directory, path, store) = seeded();
    panic_after_commit(&store.connection, write_probe_user_version, |_| {});

    let (result, events) = recovery_events_during(|| read_state(&store));
    result.expect("the store serves the committed write");
    assert_eq!(events, [recovered("security_state")]);
    assert_eq!(durable_user_version(&path), PROBE_USER_VERSION);
}

#[test]
fn participant_source_panic_before_commit_rolls_back_and_the_source_serves() {
    let (_directory, path, _store) = seeded();
    let source = SqliteSecurityParticipantSource::open(&path).expect("open the source");
    panic_before_commit(&source.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read_seal(&source));
    result.expect("the source serves after a verified rollback");
    assert_eq!(events, [recovered("security_participant_source")]);
    assert_eq!(durable_user_version(&path), 0);
}

#[test]
fn participant_source_denied_rollback_fences_the_source() {
    let (_directory, path, _store) = seeded();
    let source = SqliteSecurityParticipantSource::open(&path).expect("open the source");
    panic_with_rollback_denied(&source.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read_seal(&source));
    let fence = source.connection.fence().expect("the connection is fenced");
    assert!(matches!(fence.reason, FenceReason::RollbackFailed(_)));
    assert!(
        matches!(
            result,
            Err(Error::Invalid("source connection is fenced after a panic"))
        ),
        "{result:?}"
    );
    assert_eq!(events, [fenced("security_participant_source")]);
    assert_eq!(
        durable_user_version(&path),
        0,
        "the uncommitted write is never read"
    );
}

#[test]
fn participant_source_panic_after_commit_recovers_with_the_write_visible() {
    let (_directory, path, _store) = seeded();
    let source = SqliteSecurityParticipantSource::open(&path).expect("open the source");
    panic_after_commit(&source.connection, write_probe_user_version, |_| {});

    let (result, events) = recovery_events_during(|| read_seal(&source));
    result.expect("the source serves the committed write");
    assert_eq!(events, [recovered("security_participant_source")]);
    assert_eq!(durable_user_version(&path), PROBE_USER_VERSION);
}
