use chio_core::enterprise_identity::with_enterprise_identity_index;
use chio_core::tenant_index::{TenantIndexKey, TenantIndexKeySet};
use chio_kernel::rng::OsEntropyRng;
use chio_test_support::prelude::*;

use super::*;

const SCOPE: &str = "https://idp.example";
const DEACTIVATED_AT: u64 = 1_767_225_600;

type Store = SqliteEnterpriseIdentityStore;

fn set(active: u8, retired: &[u8]) -> TenantIndexKeySet {
    let key = |byte: u8| TenantIndexKey::from_set_key(&[byte; 32]).test_unwrap();
    TenantIndexKeySet::new(key(active), retired.iter().map(|byte| key(*byte)).collect())
        .test_unwrap()
}

/// A store at a fresh path holding `principals` under generation 1, its directory, and the
/// identities in `principals` order.
fn seeded(principals: &[&str]) -> (tempfile::TempDir, Store, Vec<EnterpriseIdentityRow>) {
    let dir = tempfile::tempdir().test_unwrap();
    let store = Store::open(dir.path().join("eid.sqlite3")).test_unwrap();
    let mut identities = Vec::new();
    for principal in principals {
        let resolved = with_enterprise_identity_index(&store, &set(1, &[]), |index| {
            index.resolve_or_insert(&OsEntropyRng, SCOPE, principal)
        });
        identities.push(resolved.test_unwrap().identity);
    }
    (dir, store, identities)
}

fn rows(store: &Store) -> EnterpriseIdentityRows {
    let mut read = None;
    store
        .transact(&mut |rows| Ok(read.replace(rows).and(None)))
        .test_unwrap();
    read.test_unwrap()
}

#[test]
fn rotation_history_and_deactivation_survive_reopen() {
    let (dir, store, identities) = seeded(&["alice", "bob"]);
    let alice = &identities[0];
    let after = set(2, &[1]);
    let in_force = with_enterprise_identity_index(&store, &after, |index| {
        let bob = index.resolve(SCOPE, "bob").test_unwrap();
        index.deactivate(&bob.identity_id, DEACTIVATED_AT)
    });
    assert_eq!(in_force, Ok(DEACTIVATED_AT));
    let committed = rows(&store);
    assert_eq!(committed.history.len(), 2);
    drop(store);

    let reopened = Store::open(dir.path().join("eid.sqlite3")).test_unwrap();
    assert_eq!(rows(&reopened), committed);
    let view = with_enterprise_identity_index(&reopened, &after, |index| {
        let bob = index.resolve(SCOPE, "bob").map(|bob| bob.deactivated_at);
        Ok((index.resolve_subject(&alice.subject)?, bob))
    });
    let expected = (Some(alice.identity_id.clone()), Some(Some(DEACTIVATED_AT)));
    assert_eq!(view, Ok(expected));
    for path in ["", ":memory:", "file:enterprise?mode=memory"] {
        use SqliteEnterpriseIdentityStoreError::InvalidPath;
        let refused = Store::open(path).err();
        assert!(matches!(refused, Some(InvalidPath)));
    }
    for _ in 0..2 {
        let restored =
            with_enterprise_identity_index(&reopened, &set(1, &[2]), |index| Ok(index.len()));
        assert_eq!(restored, Ok(2));
    }
}

#[test]
fn refused_operations_and_constraint_faults_write_nothing() {
    let (_dir, store, _) = seeded(&["alice"]);
    let before = rows(&store);
    let refused = with_enterprise_identity_index(&store, &set(2, &[1]), |index| {
        index.resolve_or_insert(&OsEntropyRng, SCOPE, "bob")?;
        Err::<(), _>(EnterpriseIdentityIndexError::UnknownIdentity)
    });
    assert_eq!(refused, Err(EnterpriseIdentityIndexError::UnknownIdentity));
    let orphan = EnterpriseSubjectHistoryRow {
        identity_id: EnterpriseIdentityId::try_from("0f".repeat(16)).test_unwrap(),
        subject: before.identities[0].subject,
    };
    let mut changes = EnterpriseIdentityChanges::default();
    changes.history.push(orphan);
    let violated = store.transact(&mut |_| Ok(Some(changes.clone())));
    let constraint = EnterpriseIdentityIndexError::StoreUnavailable(StoreFault::Constraint);
    assert_eq!(violated, Err(constraint));
    assert_eq!(rows(&store), before);
}

#[test]
fn a_store_transaction_holds_the_write_lock() {
    let (dir, store, _) = seeded(&[]);
    let raw = Connection::open(dir.path().join("eid.sqlite3")).test_unwrap();
    raw.busy_timeout(Duration::ZERO).test_unwrap();
    let mut contended = None;
    let read = store.transact(&mut |_| {
        contended = raw.execute_batch("BEGIN IMMEDIATE").err().map(fault);
        Ok(None)
    });
    assert_eq!(read, Ok(()));
    let busy = EnterpriseIdentityIndexError::StoreUnavailable(StoreFault::Busy);
    assert_eq!(contended, Some(busy));
}

#[test]
fn tampered_stored_rows_refuse_to_load() {
    let tampers = [
        "UPDATE enterprise_identities SET subject = 'esk1.' || hex(zeroblob(64))",
        "UPDATE enterprise_identities SET principal = replace(hex(zeroblob(2500)), '0', 'a')",
        "UPDATE enterprise_identities SET deactivated_at = -1",
    ];
    for tamper in tampers {
        let (dir, store, _) = seeded(&["alice"]);
        let raw = Connection::open(dir.path().join("eid.sqlite3")).test_unwrap();
        raw.execute_batch(&format!("PRAGMA ignore_check_constraints = ON; {tamper};"))
            .test_unwrap();
        let loaded = with_enterprise_identity_index(&store, &set(1, &[]), |index| Ok(index.len()));
        assert_eq!(loaded, Err(MALFORMED), "{tamper}");
    }
}
