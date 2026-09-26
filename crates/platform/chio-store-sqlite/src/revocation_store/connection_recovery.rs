//! Recovery of the revocation store's connection after a panic inside a
//! critical section, in both of its shapes: sharing the authority connection
//! under a serving owner, and standing alone on a path of its own.

use chio_kernel::{RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection, Transaction};

use super::SqliteRevocationStore;
use crate::serving_owner::{
    authority_panics_after_anchor, authority_panics_after_commit_before_anchor,
    authority_panics_before_commit, authority_panics_with_rollback_denied, ProvisionedAuthority,
    PROBE_CAPABILITY,
};
use crate::store_connection::test_support::{
    fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
    recovery_events_during,
};
use crate::store_connection::FenceReason;

const PROBE_REVOKED_AT: i64 = 1_700_000_000;

/// Write the probe revocation through the store's own statements, so a
/// recovery test's interrupted transaction holds a real revocation: the row,
/// its delta-log entry and, under a serving owner, the commit-chain entries
/// the rollback anchor tracks.
pub(crate) fn write_probe_revocation(store: &SqliteRevocationStore, transaction: &Transaction<'_>) {
    let recorded = store
        .record_revocation(transaction, PROBE_CAPABILITY, PROBE_REVOKED_AT)
        .expect("record the probe revocation");
    assert!(recorded, "the probe capability was already revoked");
}

fn fence_text(store: &SqliteRevocationStore) -> String {
    store
        .connection
        .fence()
        .expect("the connection is fenced")
        .to_string()
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_store_serves() {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    authority_panics_before_commit(&fixture.authority);

    let (revoked, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    assert!(!revoked.expect("the store serves after a verified rollback"));
    assert_eq!(events, [recovered("authority")]);
    assert!(!fixture.probe_revocation_is_durable());
}

#[test]
fn a_denied_rollback_fences_the_store() {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    authority_panics_with_rollback_denied(&fixture.authority);

    let (result, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    let fence = fence_text(&store);
    assert!(matches!(
        store.connection.fence().map(|fence| &fence.reason),
        Some(FenceReason::RollbackFailed(_))
    ));
    assert!(
        matches!(result, Err(RevocationStoreError::Sync(ref detail)) if *detail == fence),
        "{result:?}"
    );
    assert_eq!(events, [fenced("authority")]);
    assert!(
        !fixture.probe_revocation_is_durable(),
        "the uncommitted revocation is never read"
    );
}

#[test]
fn a_panic_between_commit_and_anchor_sync_refuses_until_a_reopen_reconciles() {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    authority_panics_after_commit_before_anchor(&fixture.authority);

    let (result, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    let fence = fence_text(&store);
    assert!(matches!(
        store.connection.fence().map(|fence| &fence.reason),
        Some(FenceReason::ConsistencyCheckFailed(_))
    ));
    assert!(
        matches!(result, Err(RevocationStoreError::Sync(ref detail)) if *detail == fence),
        "{result:?}"
    );
    assert_eq!(events, [fenced("authority")]);
    assert!(fixture.probe_revocation_is_durable());

    drop(store);
    let reopened = fixture.reopen();
    assert!(reopened
        .authority
        .revocation_store()
        .is_revoked(PROBE_CAPABILITY)
        .expect("the reopened store serves the committed revocation"));
}

#[test]
fn a_panic_after_anchor_sync_recovers_with_the_revocation_visible() {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    authority_panics_after_anchor(&fixture.authority);

    let (revoked, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    assert!(revoked.expect("the store serves once the anchor matches the database"));
    assert_eq!(events, [recovered("authority")]);
    assert!(fixture.probe_revocation_is_durable());
}

fn standalone() -> (tempfile::TempDir, SqliteRevocationStore) {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = SqliteRevocationStore::open(directory.path().join("revocations.db")).expect("open");
    (directory, store)
}

fn standalone_probe_is_durable(directory: &tempfile::TempDir) -> bool {
    Connection::open(directory.path().join("revocations.db"))
        .expect("open an independent reader")
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![PROBE_CAPABILITY],
            |row| row.get(0),
        )
        .expect("read the probe revocation")
}

#[test]
fn standalone_store_pairs_no_artifact_with_a_commit() {
    let (_directory, store) = standalone();
    assert!(
        !store.connection.is_anchored(),
        "opened by path nothing outside the database records a commit, so there is no phase between a commit and an anchor write"
    );
}

#[test]
fn standalone_panic_before_commit_rolls_back_and_the_store_serves() {
    let (directory, store) = standalone();
    panic_before_commit(&store.connection, |transaction| {
        write_probe_revocation(&store, transaction)
    });

    let (revoked, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    assert!(!revoked.expect("the store serves after a verified rollback"));
    assert_eq!(events, [recovered("revocation")]);
    assert!(!standalone_probe_is_durable(&directory));
}

#[test]
fn standalone_denied_rollback_fences_the_store() {
    let (directory, store) = standalone();
    panic_with_rollback_denied(&store.connection, |transaction| {
        write_probe_revocation(&store, transaction)
    });

    let (result, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    let fence = fence_text(&store);
    assert!(
        matches!(result, Err(RevocationStoreError::Sync(ref detail)) if *detail == fence),
        "{result:?}"
    );
    assert_eq!(events, [fenced("revocation")]);
    assert!(!standalone_probe_is_durable(&directory));
}

#[test]
fn standalone_panic_after_commit_recovers_with_the_revocation_visible() {
    let (directory, store) = standalone();
    panic_after_commit(
        &store.connection,
        |transaction| write_probe_revocation(&store, transaction),
        |_| {},
    );

    let (revoked, events) = recovery_events_during(|| store.is_revoked(PROBE_CAPABILITY));
    assert!(revoked.expect("the store serves the committed revocation"));
    assert_eq!(events, [recovered("revocation")]);
    assert!(standalone_probe_is_durable(&directory));
}
