//! Recovery of the budget store's connection after a panic inside a critical
//! section, in both of its shapes: sharing the authority connection under a
//! serving owner, and standing alone on a path of its own. The durable phases are induced through
//! the drivers in `crate::serving_owner`, since fifteen stores share that one
//! connection; this module asserts the outcome this store presents for each.

use chio_kernel::{BudgetStore, BudgetStoreError, RevocationStore};
use rusqlite::Connection;

use super::SqliteBudgetStore;
use crate::serving_owner::{
    authority_panics_after_anchor, authority_panics_after_commit_before_anchor,
    authority_panics_before_commit, authority_panics_with_rollback_denied, ProvisionedAuthority,
    PROBE_CAPABILITY,
};
use crate::store_connection::test_support::{
    fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
    recovery_events_during, user_version, write_probe_user_version, PROBE_USER_VERSION,
};
use crate::store_connection::FenceReason;

fn open_store(fixture: &ProvisionedAuthority) -> SqliteBudgetStore {
    fixture.authority.budget_store()
}

fn read(store: &SqliteBudgetStore) -> Result<(), BudgetStoreError> {
    store.get_usage("capability", 0).map(drop)
}

fn fence_text(store: &SqliteBudgetStore) -> String {
    store
        .connection
        .fence()
        .expect("the connection is fenced")
        .to_string()
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_store_serves() {
    let fixture = ProvisionedAuthority::open();
    let store = open_store(&fixture);
    authority_panics_before_commit(&fixture.authority);

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the store serves after a verified rollback");
    assert_eq!(events, [recovered("authority")]);
    assert!(!fixture.probe_revocation_is_durable());
}

#[test]
fn a_denied_rollback_fences_the_store() {
    let fixture = ProvisionedAuthority::open();
    let store = open_store(&fixture);
    authority_panics_with_rollback_denied(&fixture.authority);

    let (result, events) = recovery_events_during(|| read(&store));
    let fence = fence_text(&store);
    assert!(matches!(
        store.connection.fence().map(|fence| &fence.reason),
        Some(FenceReason::RollbackFailed(_))
    ));
    assert!(
        matches!(result, Err(BudgetStoreError::Invariant(ref detail)) if *detail == fence),
        "{result:?}"
    );
    assert_eq!(events, [fenced("authority")]);
    assert!(
        !fixture.probe_revocation_is_durable(),
        "the uncommitted write is never read"
    );
}

#[test]
fn a_panic_between_commit_and_anchor_sync_refuses_until_a_reopen_reconciles() {
    let fixture = ProvisionedAuthority::open();
    let store = open_store(&fixture);
    authority_panics_after_commit_before_anchor(&fixture.authority);

    let (result, events) = recovery_events_during(|| read(&store));
    let fence = fence_text(&store);
    assert!(matches!(
        store.connection.fence().map(|fence| &fence.reason),
        Some(FenceReason::ConsistencyCheckFailed(_))
    ));
    assert!(
        matches!(result, Err(BudgetStoreError::Invariant(ref detail)) if *detail == fence),
        "{result:?}"
    );
    assert_eq!(events, [fenced("authority")]);
    assert!(
        fixture.probe_revocation_is_durable(),
        "the commit landed before the panic"
    );

    drop(store);
    let reopened = fixture.reopen();
    read(&open_store(&reopened)).expect("the reopened store serves once the anchor is reconciled");
    assert!(reopened
        .authority
        .revocation_store()
        .is_revoked(PROBE_CAPABILITY)
        .expect("read the revocation"));
}

#[test]
fn a_panic_after_anchor_sync_recovers_with_the_commit_visible() {
    let fixture = ProvisionedAuthority::open();
    let store = open_store(&fixture);
    authority_panics_after_anchor(&fixture.authority);

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the store serves once the anchor matches the database");
    assert_eq!(events, [recovered("authority")]);
    assert!(fixture.probe_revocation_is_durable());
}

fn standalone() -> (tempfile::TempDir, SqliteBudgetStore) {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = SqliteBudgetStore::open(directory.path().join("budget.db")).expect("open");
    (directory, store)
}

fn standalone_user_version(directory: &tempfile::TempDir) -> i64 {
    user_version(&Connection::open(directory.path().join("budget.db")).expect("open a reader"))
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
    panic_before_commit(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the store serves after a verified rollback");
    assert_eq!(events, [recovered("budget")]);
    assert_eq!(standalone_user_version(&directory), 0);
}

#[test]
fn standalone_denied_rollback_fences_the_store() {
    let (directory, store) = standalone();
    panic_with_rollback_denied(&store.connection, write_probe_user_version);

    let (result, events) = recovery_events_during(|| read(&store));
    let fence = fence_text(&store);
    assert!(
        matches!(result, Err(BudgetStoreError::Invariant(ref detail)) if *detail == fence),
        "{result:?}"
    );
    assert_eq!(events, [fenced("budget")]);
    assert_eq!(
        standalone_user_version(&directory),
        0,
        "the uncommitted write is never read"
    );
}

#[test]
fn standalone_panic_after_commit_recovers_with_the_write_visible() {
    let (directory, store) = standalone();
    panic_after_commit(&store.connection, write_probe_user_version, |_| {});

    let (result, events) = recovery_events_during(|| read(&store));
    result.expect("the store serves the committed write");
    assert_eq!(events, [recovered("budget")]);
    assert_eq!(standalone_user_version(&directory), PROBE_USER_VERSION);
}
