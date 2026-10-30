use alloc::vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU8, Ordering};

use chio_test_support::prelude::*;

use super::*;
use crate::tenant_index::TenantIndexKey;

const SCOPE: &str = "https://idp.example";
const DEACTIVATED_AT: u64 = 1_767_225_600;

type Error = EnterpriseIdentityIndexError;
type HistoryRow = EnterpriseSubjectHistoryRow;

/// In-memory store holding the committed rows and the count of committed change sets.
#[derive(Default)]
struct MemoryStore(RefCell<EnterpriseIdentityRows>, Cell<usize>);

impl MemoryStore {
    fn rows(&self) -> EnterpriseIdentityRows {
        self.0.borrow().clone()
    }

    fn commits(&self) -> usize {
        self.1.get()
    }
}

impl EnterpriseIdentityStore for MemoryStore {
    fn transact(&self, transaction: &mut EnterpriseIdentityTransaction<'_>) -> Result<(), Error> {
        let Some(changes) = transaction(self.rows())? else {
            return Ok(());
        };
        let mut rows = self.0.borrow_mut();
        rows.history
            .retain(|row| !changes.restored.contains(&row.subject));
        rows.identities.extend(changes.inserted);
        for row in &mut rows.identities {
            let id = &row.identity_id;
            if let Some((_, subject)) = changes.rekeyed.iter().find(|(at, _)| at == id) {
                row.subject = *subject;
            }
            if let Some((_, at)) = changes.deactivated.iter().find(|(of, _)| of == id) {
                row.deactivated_at.get_or_insert(*at);
            }
        }
        rows.history.extend(changes.history);
        self.1.set(self.1.get() + 1);
        Ok(())
    }
}

/// Fills each draw with the next counter value, starting at 1.
struct SequenceRng(AtomicU8);

impl Rng for SequenceRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        dest.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

fn rng() -> SequenceRng {
    SequenceRng(AtomicU8::new(1))
}

fn key(byte: u8) -> TenantIndexKey {
    TenantIndexKey::from_set_key(&[byte; 32]).test_unwrap()
}

fn set(active: u8, retired: &[u8]) -> TenantIndexKeySet {
    TenantIndexKeySet::new(key(active), retired.iter().map(|byte| key(*byte)).collect())
        .test_unwrap()
}

fn subject(keys: &TenantIndexKeySet, principal: &str) -> EnterpriseSubjectKey {
    EnterpriseSubjectKey::derive(keys, SCOPE, principal).test_unwrap()
}

fn id(n: usize) -> EnterpriseIdentityId {
    EnterpriseIdentityId::try_from(alloc::format!("{n:032x}")).test_unwrap()
}

fn insert(store: &MemoryStore, keys: &TenantIndexKeySet, r: &dyn Rng, p: &str) -> ResolvedIdentity {
    let resolved =
        with_enterprise_identity_index(store, keys, |index| index.resolve_or_insert(r, SCOPE, p));
    resolved.test_unwrap()
}

fn length(store: &MemoryStore, keys: &TenantIndexKeySet) -> Result<usize, Error> {
    with_enterprise_identity_index(store, keys, |index| Ok(index.len()))
}

fn unknown(byte: u8) -> Error {
    let key_id = *key(byte).key_id();
    let unknown = TenantBindingError::TenantIndexKeyUnknown { key_id };
    Error::Subject(EnterpriseSubjectError::Index(unknown))
}

fn identity_row(n: usize, principal: &str, subject: EnterpriseSubjectKey) -> EnterpriseIdentityRow {
    EnterpriseIdentityRow {
        identity_id: id(n),
        provider_scope: SCOPE.into(),
        principal: principal.into(),
        subject,
        deactivated_at: None,
    }
}

fn history_row(identity_id: EnterpriseIdentityId, subject: EnterpriseSubjectKey) -> HistoryRow {
    HistoryRow {
        identity_id,
        subject,
    }
}

#[test]
fn insert_resolves_by_principal_and_a_read_commits_nothing() {
    let store = MemoryStore::default();
    let (keys, rng) = (set(1, &[]), rng());
    let alice = insert(&store, &keys, &rng, "alice");
    assert!(alice.inserted);
    assert_eq!(alice.identity.identity_id.as_str(), "01".repeat(16));
    assert_eq!(alice.identity.subject, subject(&keys, "alice"));
    let again = insert(&store, &keys, &rng, "alice");
    assert_eq!((again.identity, again.inserted), (alice.identity, false));
    let other = with_enterprise_identity_index(&store, &keys, |index| {
        index.resolve_or_insert(&rng, "https://other-idp.example", "alice")
    });
    assert!(other.test_unwrap().inserted);
    assert_eq!(store.rows().identities.len(), 2);
    assert_eq!(store.commits(), 2);
}

#[test]
fn rotation_rederives_every_identity_in_one_commit_and_keeps_history() {
    let store = MemoryStore::default();
    let (before, after, rng) = (set(1, &[]), set(2, &[1]), rng());
    let principals = ["alice", "bob", "carol"];
    let ids = principals.map(|p| insert(&store, &before, &rng, p).identity.identity_id);
    let inserted = store.rows();
    let refused = with_enterprise_identity_index(&store, &after, |index| {
        index.resolve_or_insert(&rng, SCOPE, "dave")?;
        Err::<(), _>(Error::UnknownIdentity)
    });
    assert_eq!(refused, Err(Error::UnknownIdentity));
    assert_eq!(store.rows(), inserted);

    let presented = with_enterprise_identity_index(&store, &after, |index| {
        let fresh = index.resolve_presented(SCOPE, "alice", &subject(&after, "alice"))?;
        let stale = index.resolve_presented(SCOPE, "alice", &subject(&before, "alice"))?;
        Ok([fresh.identity_id, stale.identity_id])
    });
    assert_eq!(presented, Ok([ids[0].clone(), ids[0].clone()]));
    length(&store, &after).test_unwrap();
    assert_eq!(store.commits(), principals.len() + 1);
    let rows = store.rows();
    for (n, p) in principals.iter().enumerate() {
        assert_eq!(rows.identities[n].subject, subject(&after, p));
        let prior = history_row(ids[n].clone(), subject(&before, p));
        assert_eq!(rows.history[n], prior);
    }
}

#[test]
fn history_join_after_rotation_and_reactivation() {
    let store = MemoryStore::default();
    let alice = insert(&store, &set(1, &[]), &rng(), "alice").identity;
    let (old, after) = (alice.subject, set(2, &[1]));
    let new = subject(&after, "alice");
    let relabel = |from: &EnterpriseSubjectKey, to: u8| {
        let value = from.keyed_value().value.to_bare_hex();
        let text = alloc::format!("esk1.{}.{value}", key(to).key_id().to_bare_hex());
        EnterpriseSubjectKey::parse(&text).test_unwrap()
    };
    let foreign = subject(&set(7, &[]), "alice");
    let joined: Result<Vec<_>, _> = with_enterprise_identity_index(&store, &after, |index| {
        assert_eq!(index.history_of(&alice.identity_id), vec![old]);
        let presented = index.resolve_presented(SCOPE, "alice", &foreign);
        assert_eq!(presented, Err(unknown(7)));
        assert_eq!(index.resolve_subject(&foreign), Err(unknown(7)));
        let probes = [old, new, relabel(&old, 2), relabel(&new, 1)];
        probes.iter().map(|p| index.resolve_subject(p)).collect()
    });
    let owner = Some(alice.identity_id.clone());
    assert_eq!(joined, Ok(vec![owner.clone(), owner, None, None]));
    assert_eq!(length(&store, &set(3, &[2])), Err(unknown(1)));

    let restored = with_enterprise_identity_index(&store, &set(1, &[2]), |index| {
        let history = index.history_of(&alice.identity_id);
        Ok((index.resolve(SCOPE, "alice"), history))
    });
    assert_eq!(restored, Ok((Some(alice), vec![new])));
    assert_eq!(length(&store, &set(1, &[2])), Ok(1));
}

#[test]
fn deactivation_holds_across_rotation_and_refuses_out_of_range_times() {
    let (store, rng, after) = (MemoryStore::default(), rng(), set(2, &[1]));
    let alice = insert(&store, &set(1, &[]), &rng, "alice").identity;
    let deactivate = |keys: &TenantIndexKeySet, identity_id: &EnterpriseIdentityId, at| {
        with_enterprise_identity_index(&store, keys, |index| index.deactivate(identity_id, at))
    };
    let first = deactivate(&set(1, &[]), &alice.identity_id, DEACTIVATED_AT);
    assert_eq!(first, Ok(DEACTIVATED_AT));
    let recreated = insert(&store, &after, &rng, "alice");
    assert!(!recreated.inserted);
    assert_eq!(recreated.identity.identity_id, alice.identity_id);
    assert_eq!(recreated.identity.deactivated_at, Some(DEACTIVATED_AT));
    let commits = store.commits();
    let later = deactivate(&after, &alice.identity_id, DEACTIVATED_AT + 60);
    assert_eq!(later, Ok(DEACTIVATED_AT));
    let missing = deactivate(&after, &id(0x0f), DEACTIVATED_AT);
    assert_eq!(missing, Err(Error::UnknownIdentity));
    let late = deactivate(&after, &alice.identity_id, u64::MAX);
    assert_eq!(late, Err(Error::InvalidTime));
    assert_eq!(store.commits(), commits);
}

#[test]
fn presented_principals_and_ids_must_be_in_bounds_and_verify() {
    let (store, keys) = (MemoryStore::default(), set(1, &[]));
    insert(&store, &keys, &rng(), "alice");
    let bob = subject(&keys, "bob");
    let long = "a".repeat(ENTERPRISE_PRINCIPAL_MAX_BYTES + 1);
    let invalid = [(SCOPE, ""), ("", "a"), (SCOPE, "a\0b"), (&*long, "a")];
    let probes = with_enterprise_identity_index(&store, &keys, |index| {
        let mismatch = Error::Subject(EnterpriseSubjectError::Index(TenantBindingError::Mismatch));
        assert_eq!(index.resolve_presented(SCOPE, "alice", &bob), Err(mismatch));
        let unindexed = index.resolve_presented(SCOPE, "bob", &bob);
        assert_eq!(unindexed, Err(Error::UnknownIdentity));
        let mut refusals = Vec::new();
        for (scope, principal) in invalid {
            refusals.push(index.resolve_presented(scope, principal, &bob).err());
            refusals.push(index.resolve_or_insert(&rng(), scope, principal).err());
        }
        Ok(refusals)
    });
    let refusals = vec![Some(Error::InvalidPrincipal); 2 * invalid.len()];
    assert_eq!(probes, Ok(refusals));
    assert_eq!(store.commits(), 1);
    for text in ["", &"0A".repeat(16), &"0a".repeat(15), "scim-0123"] {
        let parsed = EnterpriseIdentityId::try_from(String::from(text));
        assert_eq!(parsed, Err(Error::MalformedIdentityId));
    }
}

#[test]
fn tampered_rows_refuse_to_load_and_are_never_replaced() {
    use EnterpriseIdentityIndexError::{
        DuplicateIdentityId, DuplicatePrincipal, DuplicateSubject, MalformedRow, OrphanHistory,
    };
    let keys = set(1, &[]);
    let (a, b, row) = (subject(&keys, "alice"), subject(&keys, "bob"), identity_row);
    let (a1, mut late) = (row(1, "alice", a), row(1, "alice", a));
    late.deactivated_at = Some(u64::MAX);
    let mismatch = Error::Subject(EnterpriseSubjectError::Index(TenantBindingError::Mismatch));
    let crowd = vec![a1.clone(); ENTERPRISE_IDENTITY_MAX_IDENTITIES + 1];
    let long_history = vec![history_row(id(1), a); ENTERPRISE_IDENTITY_MAX_HISTORY + 1];
    let cases = [
        (vec![row(1, "alice", b)], vec![], mismatch),
        (
            vec![a1.clone(), row(2, "alice", a)],
            vec![],
            DuplicatePrincipal,
        ),
        (
            vec![a1.clone(), row(1, "bob", b)],
            vec![],
            DuplicateIdentityId,
        ),
        (vec![a1.clone()], vec![history_row(id(2), b)], OrphanHistory),
        (
            vec![a1.clone()],
            vec![history_row(id(1), a)],
            DuplicateSubject,
        ),
        (vec![row(1, "", a)], vec![], MalformedRow),
        (vec![late], vec![], MalformedRow),
        (crowd, vec![], MalformedRow),
        (vec![], long_history, MalformedRow),
    ];
    for (identities, history, expected) in cases {
        let store = MemoryStore::default();
        store.0.borrow_mut().identities = identities;
        store.0.borrow_mut().history = history;
        assert_eq!((length(&store, &keys), store.commits()), (Err(expected), 0));
    }
}

#[test]
fn a_full_index_refuses_inserts_and_rekeys_but_still_deactivates() {
    let generations: Vec<TenantIndexKeySet> = (1..=4).map(|byte| set(byte, &[])).collect();
    let keys = set(5, &[1, 2, 3, 4]);
    let mut rows = EnterpriseIdentityRows::default();
    for n in 0..ENTERPRISE_IDENTITY_MAX_IDENTITIES {
        let p = alloc::format!("p{n}");
        rows.identities
            .push(identity_row(n, &p, subject(&keys, &p)));
        for retired in &generations {
            rows.history.push(history_row(id(n), subject(retired, &p)));
        }
    }
    assert_eq!(rows.history.len(), ENTERPRISE_IDENTITY_MAX_HISTORY);
    let store = MemoryStore(RefCell::new(rows), Cell::new(0));
    let outcome = with_enterprise_identity_index(&store, &keys, |index| {
        let in_force = index.deactivate(&id(0), DEACTIVATED_AT)?;
        Ok((in_force, index.resolve_or_insert(&rng(), SCOPE, "newcomer")))
    });
    assert_eq!(outcome, Ok((DEACTIVATED_AT, Err(Error::CapacityExhausted))));
    assert_eq!(store.commits(), 1);
    let rotated = length(&store, &set(6, &[1, 2, 3, 4, 5]));
    assert_eq!(rotated, Err(Error::HistoryExhausted));
    assert_eq!(store.commits(), 1);
}
