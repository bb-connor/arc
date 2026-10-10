//! Recovery of the sealed decoy registry's connection after a panic inside a
//! critical section. Every mutation is one RAII transaction and nothing
//! outside the database records a commit, so there is no phase between a
//! commit and an anchor write.

use chio_security_types::ports::{Digest32, PortErrorKind, SealedDecoyRegistryStore, TenantId};
use chio_security_types::DecoyArtifactLookup;
use rusqlite::Connection;
use tempfile::TempDir;

use super::SqliteSealedDecoyRegistryStore;
use crate::store_connection::test_support::{
    fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
    recovery_events_during, user_version, write_probe_user_version, PROBE_USER_VERSION,
};
use crate::store_connection::FenceReason;

fn open() -> (TempDir, SqliteSealedDecoyRegistryStore) {
    let directory = tempfile::tempdir().expect("tempdir");
    let store =
        SqliteSealedDecoyRegistryStore::open(directory.path().join("decoys.db")).expect("open");
    (directory, store)
}

fn read(store: &SqliteSealedDecoyRegistryStore) -> Result<(), PortErrorKind> {
    store
        .load_by_id(&DecoyArtifactLookup {
            tenant_id: TenantId::new("tenant").expect("tenant id"),
            artifact_token: Digest32::new([7; 32]),
        })
        .map(drop)
        .map_err(|error| error.kind())
}

fn durable_user_version(directory: &TempDir) -> i64 {
    user_version(&Connection::open(directory.path().join("decoys.db")).expect("open a reader"))
}

#[test]
fn the_registry_pairs_no_artifact_with_a_commit() {
    let (_directory, store) = open();
    assert!(!store.connection.is_anchored());
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_registry_serves() {
    let (directory, store) = open();
    panic_before_commit(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the registry serves after a verified rollback");
    assert_eq!(events, [recovered("sealed_decoy_registry")]);
    assert_eq!(durable_user_version(&directory), 0);
}

#[test]
fn a_denied_rollback_fences_the_registry() {
    let (directory, store) = open();
    panic_with_rollback_denied(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read(&store));
    let fence = store.connection.fence().expect("the connection is fenced");
    assert!(matches!(fence.reason, FenceReason::RollbackFailed(_)));
    assert_eq!(result, Err(PortErrorKind::Unavailable));
    assert_eq!(events, [fenced("sealed_decoy_registry")]);
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
    result.expect("the registry serves the committed write");
    assert_eq!(events, [recovered("sealed_decoy_registry")]);
    assert_eq!(durable_user_version(&directory), PROBE_USER_VERSION);
}
