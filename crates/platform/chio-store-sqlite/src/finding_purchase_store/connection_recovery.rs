//! Recovery of the finding purchase store's share of the authority connection after a
//! panic inside a critical section. The durable phases are induced through
//! the drivers in `crate::serving_owner`, since fifteen stores share that one
//! connection; this module asserts the outcome this store presents for each.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_kernel::RevocationStore;

use super::{FindingPurchaseStoreError, SqliteFindingPurchaseStore};
use crate::serving_owner::{
    authority_panics_after_anchor, authority_panics_after_commit_before_anchor,
    authority_panics_before_commit, authority_panics_with_rollback_denied, ProvisionedAuthority,
    PROBE_CAPABILITY,
};
use crate::store_connection::test_support::{fenced, recovered, recovery_events_during};
use crate::store_connection::FenceReason;

fn open_store(fixture: &ProvisionedAuthority) -> SqliteFindingPurchaseStore {
    fixture.authority.finding_purchase_store()
}

fn read(store: &SqliteFindingPurchaseStore) -> Result<(), FindingPurchaseStoreError> {
    store.sales_blocked("listing").map(drop)
}

fn fence_text(store: &SqliteFindingPurchaseStore) -> String {
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
        matches!(result, Err(FindingPurchaseStoreError::Unavailable(ref detail)) if *detail == fence),
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
        matches!(result, Err(FindingPurchaseStoreError::Unavailable(ref detail)) if *detail == fence),
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
