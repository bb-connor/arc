use std::sync::atomic::{AtomicU8, Ordering};

use chio_core::enterprise_identity::{with_enterprise_identity_index, ResolvedIdentity};
use chio_core::rng::{Rng, RngError};
use chio_core::tenant_index::{TenantIndexKey, TenantIndexKeySet};
use chio_test_support::prelude::*;

use super::*;

const SCOPE: &str = "https://idp.example";

struct SequenceRng(AtomicU8);

impl Rng for SequenceRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        dest.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

fn set(active: u8, retired: &[u8]) -> TenantIndexKeySet {
    let key = |byte: u8| TenantIndexKey::from_set_key(&[byte; 32]).test_unwrap();
    TenantIndexKeySet::new(key(active), retired.iter().map(|byte| key(*byte)).collect())
        .test_unwrap()
}

fn store_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("enterprise-identities.sqlite3")
}

fn insert(
    store: &SqliteEnterpriseIdentityStore,
    keys: &TenantIndexKeySet,
    rng: &dyn Rng,
    principal: &str,
) -> ResolvedIdentity {
    with_enterprise_identity_index(store, keys, |index| {
        index.resolve_or_insert(rng, SCOPE, principal)
    })
    .test_unwrap()
}

fn rows(store: &SqliteEnterpriseIdentityStore) -> EnterpriseIdentityRows {
    store.transact(|rows| Ok((rows, None))).test_unwrap()
}

#[test]
fn identities_rotation_history_and_deactivation_survive_reopen() {
    let dir = tempfile::tempdir().test_unwrap();
    let rng = SequenceRng(AtomicU8::new(1));
    let before = set(1, &[]);
    let after = set(2, &[1]);
    let store = SqliteEnterpriseIdentityStore::open(store_path(&dir)).test_unwrap();
    let alice = insert(&store, &before, &rng, "alice").identity;
    let bob = insert(&store, &before, &rng, "bob").identity;
    let in_force = with_enterprise_identity_index(&store, &after, |index| {
        index.deactivate(&bob.identity_id, u64::MAX)
    });
    assert_eq!(in_force, Ok(u64::MAX));
    let committed = rows(&store);
    drop(store);

    let reopened = SqliteEnterpriseIdentityStore::open(store_path(&dir)).test_unwrap();
    assert_eq!(rows(&reopened), committed);
    assert_eq!(committed.history.len(), 2);
    let resolved = with_enterprise_identity_index(&reopened, &after, |index| {
        Ok((
            index.resolve(SCOPE, "bob"),
            index.resolve_subject(&alice.subject)?,
        ))
    });
    let (bob_now, attributed) = resolved.test_unwrap();
    assert_eq!(bob_now.test_unwrap().deactivated_at, Some(u64::MAX));
    assert_eq!(attributed, Some(alice.identity_id));
}

#[test]
fn a_refused_operation_rolls_back_the_rekey_and_its_changes() {
    let dir = tempfile::tempdir().test_unwrap();
    let rng = SequenceRng(AtomicU8::new(1));
    let store = SqliteEnterpriseIdentityStore::open(store_path(&dir)).test_unwrap();
    insert(&store, &set(1, &[]), &rng, "alice");
    let before = rows(&store);

    let refused = with_enterprise_identity_index(&store, &set(2, &[1]), |index| {
        index.resolve_or_insert(&rng, SCOPE, "bob")?;
        Err::<(), _>(EnterpriseIdentityIndexError::UnknownIdentity)
    });
    assert_eq!(refused, Err(EnterpriseIdentityIndexError::UnknownIdentity));
    assert_eq!(rows(&store), before);
}

#[test]
fn a_malformed_stored_row_refuses_to_load() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteEnterpriseIdentityStore::open(store_path(&dir)).test_unwrap();
    insert(
        &store,
        &set(1, &[]),
        &SequenceRng(AtomicU8::new(1)),
        "alice",
    );
    drop(store);
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    raw.execute(
        "UPDATE enterprise_identities SET subject = ?1",
        ["a1".repeat(32)],
    )
    .test_unwrap();
    drop(raw);

    let reopened = SqliteEnterpriseIdentityStore::open(store_path(&dir)).test_unwrap();
    let refused = with_enterprise_identity_index(&reopened, &set(1, &[]), |index| Ok(index.len()));
    assert_eq!(refused, Err(EnterpriseIdentityIndexError::MalformedRow));
}

#[test]
fn in_memory_and_uri_paths_are_refused() {
    for path in ["", ":memory:", "file:enterprise?mode=memory"] {
        assert!(matches!(
            SqliteEnterpriseIdentityStore::open(path),
            Err(SqliteEnterpriseIdentityStoreError::InvalidPath)
        ));
    }
}
