use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU8, Ordering};

use chio_test_support::prelude::*;

use super::*;
use crate::root_authority::Sha256Digest;
use crate::tenant_index::TenantIndexKey;

const SCOPE: &str = "https://idp.example";
const DEACTIVATED_AT: u64 = 1_767_225_600;

/// In-memory store: `rows` are the committed rows, and `commits` counts replacements.
#[derive(Default)]
struct MemoryStore {
    rows: RefCell<EnterpriseIdentityRows>,
    commits: Cell<usize>,
}

impl MemoryStore {
    fn holding(rows: EnterpriseIdentityRows) -> Self {
        Self {
            rows: RefCell::new(rows),
            commits: Cell::new(0),
        }
    }

    fn rows(&self) -> EnterpriseIdentityRows {
        self.rows.borrow().clone()
    }
}

impl EnterpriseIdentityStore for MemoryStore {
    fn transact<R>(
        &self,
        transaction: impl FnOnce(EnterpriseIdentityRows) -> EnterpriseIdentityTransaction<R>,
    ) -> Result<R, EnterpriseIdentityIndexError> {
        let (outcome, replaced) = transaction(self.rows())?;
        if let Some(rows) = replaced {
            self.rows.replace(rows);
            self.commits.set(self.commits.get() + 1);
        }
        Ok(outcome)
    }
}

struct SequenceRng(AtomicU8);

impl SequenceRng {
    fn new() -> Self {
        Self(AtomicU8::new(1))
    }
}

impl Rng for SequenceRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        dest.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("entropy offline"))
    }
}

fn key(byte: u8) -> TenantIndexKey {
    TenantIndexKey::from_set_key(&[byte; 32]).test_unwrap()
}

fn key_id(byte: u8) -> Sha256Digest {
    *key(byte).key_id()
}

fn set(active: u8, retired: &[u8]) -> TenantIndexKeySet {
    TenantIndexKeySet::new(key(active), retired.iter().map(|byte| key(*byte)).collect())
        .test_unwrap()
}

fn subject(keys: &TenantIndexKeySet, principal: &str) -> EnterpriseSubjectKey {
    EnterpriseSubjectKey::derive(keys, SCOPE, principal).test_unwrap()
}

fn id(byte: &str) -> EnterpriseIdentityId {
    EnterpriseIdentityId::try_from(byte.repeat(16)).test_unwrap()
}

fn insert(
    store: &MemoryStore,
    keys: &TenantIndexKeySet,
    rng: &dyn Rng,
    principal: &str,
) -> ResolvedIdentity {
    with_enterprise_identity_index(store, keys, |index| {
        index.resolve_or_insert(rng, SCOPE, principal)
    })
    .test_unwrap()
}

fn length(
    store: &MemoryStore,
    keys: &TenantIndexKeySet,
) -> Result<usize, EnterpriseIdentityIndexError> {
    with_enterprise_identity_index(store, keys, |index| Ok(index.len()))
}

fn unknown(byte: u8) -> EnterpriseIdentityIndexError {
    EnterpriseIdentityIndexError::Subject(EnterpriseSubjectError::Index(
        TenantBindingError::TenantIndexKeyUnknown {
            key_id: key_id(byte),
        },
    ))
}

fn identity_row(
    identity_id: &EnterpriseIdentityId,
    principal: &str,
    subject: EnterpriseSubjectKey,
) -> EnterpriseIdentityRow {
    EnterpriseIdentityRow {
        identity_id: identity_id.clone(),
        provider_scope: SCOPE.into(),
        principal: principal.into(),
        subject,
        deactivated_at: None,
    }
}

#[test]
fn insert_resolves_by_principal_and_stores_only_the_keyed_subject() {
    let store = MemoryStore::default();
    let keys = set(1, &[]);
    let rng = SequenceRng::new();
    let alice = insert(&store, &keys, &rng, "alice");
    assert!(alice.inserted);
    assert_eq!(alice.identity.identity_id, id("01"));
    assert_eq!(alice.identity.subject, subject(&keys, "alice"));
    assert_eq!(alice.identity.deactivated_at, None);

    let again = insert(&store, &keys, &rng, "alice");
    assert_eq!(again.identity, alice.identity);
    assert!(!again.inserted);
    let bob = insert(&store, &keys, &rng, "bob");
    assert_ne!(bob.identity.identity_id, alice.identity.identity_id);

    let rows = store.rows();
    assert_eq!(rows.identities.len(), 2);
    assert!(rows.history.is_empty());
    assert_eq!(store.commits.get(), 2);
}

#[test]
fn rotation_rederives_every_identity_in_one_commit_and_keeps_history() {
    let store = MemoryStore::default();
    let before = set(1, &[]);
    let rng = SequenceRng::new();
    let principals = ["alice", "bob", "carol"];
    let ids: Vec<EnterpriseIdentityId> = principals
        .iter()
        .map(|principal| {
            insert(&store, &before, &rng, principal)
                .identity
                .identity_id
        })
        .collect();
    let inserted = store.rows();

    let after = set(2, &[1]);
    let refused = with_enterprise_identity_index(&store, &after, |_| {
        Err::<(), _>(EnterpriseIdentityIndexError::UnknownIdentity)
    });
    assert_eq!(refused, Err(EnterpriseIdentityIndexError::UnknownIdentity));
    assert_eq!(store.rows(), inserted);

    assert_eq!(length(&store, &after), Ok(principals.len()));
    let rows = store.rows();
    assert_eq!(rows.history.len(), principals.len());
    for ((principal, identity_id), row) in principals.iter().zip(&ids).zip(&rows.identities) {
        assert_eq!(&row.identity_id, identity_id);
        assert_eq!(row.subject, subject(&after, principal));
        assert!(rows.history.contains(&EnterpriseSubjectHistoryRow {
            identity_id: identity_id.clone(),
            subject: subject(&before, principal),
        }));
    }

    let commits = store.commits.get();
    let presented = with_enterprise_identity_index(&store, &after, |index| {
        let fresh = index.resolve_presented(SCOPE, "alice", &subject(&after, "alice"))?;
        let stale = index.resolve_presented(SCOPE, "alice", &subject(&before, "alice"))?;
        Ok((
            fresh.identity_id,
            stale.identity_id,
            fresh.subject.key_id() == &key_id(2),
        ))
    });
    assert_eq!(presented, Ok((ids[0].clone(), ids[0].clone(), true)));
    assert_eq!(store.commits.get(), commits);
}

#[test]
fn history_join_after_rotation() {
    let store = MemoryStore::default();
    let alice = insert(&store, &set(1, &[]), &SequenceRng::new(), "alice").identity;
    let old_receipt_subject = alice.subject;

    let after = set(2, &[1]);
    let new_receipt_subject = subject(&after, "alice");
    let relabeled = EnterpriseSubjectKey::parse(&alloc::format!(
        "esk1.{}.{}",
        key_id(2).to_bare_hex(),
        old_receipt_subject.keyed_value().value.to_bare_hex()
    ))
    .test_unwrap();
    let crossed = EnterpriseSubjectKey::parse(&alloc::format!(
        "esk1.{}.{}",
        key_id(1).to_bare_hex(),
        new_receipt_subject.keyed_value().value.to_bare_hex()
    ))
    .test_unwrap();
    let joined = with_enterprise_identity_index(&store, &after, |index| {
        assert_eq!(
            index.history_of(&alice.identity_id),
            alloc::vec![old_receipt_subject]
        );
        Ok([
            index.resolve_subject(&old_receipt_subject)?,
            index.resolve_subject(&new_receipt_subject)?,
            index.resolve_subject(&relabeled)?,
            index.resolve_subject(&crossed)?,
        ])
    })
    .test_unwrap();
    assert_eq!(
        joined,
        [
            Some(alice.identity_id.clone()),
            Some(alice.identity_id),
            None,
            None
        ]
    );
}

#[test]
fn unknown_generation_refuses_startup_and_lookup() {
    let store = MemoryStore::default();
    insert(&store, &set(1, &[]), &SequenceRng::new(), "alice");

    assert_eq!(length(&store, &set(2, &[])), Err(unknown(1)));
    length(&store, &set(2, &[1])).test_unwrap();
    assert_eq!(length(&store, &set(3, &[2])), Err(unknown(1)));

    let keys = set(2, &[1]);
    let foreign = subject(&set(7, &[]), "alice");
    let by_subject =
        with_enterprise_identity_index(&store, &keys, |index| index.resolve_subject(&foreign));
    assert_eq!(by_subject, Err(unknown(7)));
    let presented = with_enterprise_identity_index(&store, &keys, |index| {
        index.resolve_presented(SCOPE, "alice", &foreign)
    });
    assert_eq!(presented, Err(unknown(7)));
}

#[test]
fn scim_deactivate_after_rotation_holds() {
    let store = MemoryStore::default();
    let before = set(1, &[]);
    let rng = SequenceRng::new();
    let alice = insert(&store, &before, &rng, "alice").identity;
    let deactivated = with_enterprise_identity_index(&store, &before, |index| {
        index.deactivate(&alice.identity_id, DEACTIVATED_AT)
    });
    assert_eq!(deactivated, Ok(DEACTIVATED_AT));

    let after = set(2, &[1]);
    let recreated = insert(&store, &after, &rng, "alice");
    assert!(!recreated.inserted);
    assert_eq!(recreated.identity.identity_id, alice.identity_id);
    assert_eq!(recreated.identity.deactivated_at, Some(DEACTIVATED_AT));
    let later = with_enterprise_identity_index(&store, &after, |index| {
        index.deactivate(&alice.identity_id, DEACTIVATED_AT + 60)
    });
    assert_eq!(later, Ok(DEACTIVATED_AT));
    let missing = with_enterprise_identity_index(&store, &after, |index| {
        index.deactivate(&id("0f"), DEACTIVATED_AT)
    });
    assert_eq!(missing, Err(EnterpriseIdentityIndexError::UnknownIdentity));
}

#[test]
fn no_duplicate_identity_across_rotation() {
    let store = MemoryStore::default();
    let rng = SequenceRng::new();
    let first = insert(&store, &set(1, &[]), &rng, "alice").identity;
    let second = insert(&store, &set(2, &[1]), &rng, "alice");
    let third = insert(&store, &set(3, &[1, 2]), &rng, "alice");
    assert!(!second.inserted && !third.inserted);
    assert_eq!(second.identity.identity_id, first.identity_id);
    assert_eq!(third.identity.identity_id, first.identity_id);
    let other_scope = with_enterprise_identity_index(&store, &set(3, &[1, 2]), |index| {
        let other = index.resolve_or_insert(&rng, "https://other-idp.example", "alice")?;
        Ok((
            other,
            index.len(),
            index.history_of(&first.identity_id).len(),
        ))
    })
    .test_unwrap();
    assert!(other_scope.0.inserted);
    assert_ne!(other_scope.0.identity.identity_id, first.identity_id);
    assert_eq!(other_scope.1, 2);
    assert_eq!(other_scope.2, 2);
}

#[test]
fn a_reactivated_generation_moves_its_subject_back_out_of_history() {
    let store = MemoryStore::default();
    let alice = insert(&store, &set(1, &[]), &SequenceRng::new(), "alice").identity;
    length(&store, &set(2, &[1])).test_unwrap();
    let restored = with_enterprise_identity_index(&store, &set(1, &[2]), |index| {
        Ok((
            index.resolve(SCOPE, "alice"),
            index.history_of(&alice.identity_id),
        ))
    })
    .test_unwrap();
    assert_eq!(restored.0, Some(alice.clone()));
    assert_eq!(restored.1, alloc::vec![subject(&set(2, &[]), "alice")]);
}

#[test]
fn presented_subject_must_verify_and_be_indexed() {
    let store = MemoryStore::default();
    let keys = set(1, &[]);
    insert(&store, &keys, &SequenceRng::new(), "alice");
    let bob = subject(&keys, "bob");
    let as_alice = with_enterprise_identity_index(&store, &keys, |index| {
        index.resolve_presented(SCOPE, "alice", &bob)
    });
    assert_eq!(
        as_alice,
        Err(EnterpriseIdentityIndexError::Subject(
            EnterpriseSubjectError::Index(TenantBindingError::Mismatch)
        ))
    );
    let unindexed = with_enterprise_identity_index(&store, &keys, |index| {
        index.resolve_presented(SCOPE, "bob", &bob)
    });
    assert_eq!(
        unindexed,
        Err(EnterpriseIdentityIndexError::UnknownIdentity)
    );
}

#[test]
fn identity_ids_are_drawn_whole_and_validated() {
    let store = MemoryStore::default();
    let refused = with_enterprise_identity_index(&store, &set(1, &[]), |index| {
        index.resolve_or_insert(&FailingRng, SCOPE, "alice")
    });
    assert_eq!(
        refused,
        Err(EnterpriseIdentityIndexError::Entropy(RngError(
            "entropy offline"
        )))
    );
    assert_eq!(store.commits.get(), 0);
    for text in [
        "",
        "0A".repeat(16).as_str(),
        "0a".repeat(15).as_str(),
        "scim-0123",
    ] {
        let parsed = EnterpriseIdentityId::try_from(String::from(text));
        assert_eq!(
            parsed,
            Err(EnterpriseIdentityIndexError::MalformedIdentityId)
        );
    }
}

#[test]
fn tampered_rows_refuse_to_load_and_are_never_replaced() {
    let keys = set(1, &[]);
    let (alice, bob) = (subject(&keys, "alice"), subject(&keys, "bob"));
    let (id_a, id_b) = (id("0a"), id("0b"));
    let history = |identity_id: &EnterpriseIdentityId, subject| EnterpriseSubjectHistoryRow {
        identity_id: identity_id.clone(),
        subject,
    };
    let cases = [
        (
            alloc::vec![identity_row(&id_a, "alice", bob)],
            alloc::vec![],
            EnterpriseIdentityIndexError::Subject(EnterpriseSubjectError::Index(
                TenantBindingError::Mismatch,
            )),
        ),
        (
            alloc::vec![
                identity_row(&id_a, "alice", alice),
                identity_row(&id_b, "alice", alice)
            ],
            alloc::vec![],
            EnterpriseIdentityIndexError::DuplicatePrincipal,
        ),
        (
            alloc::vec![
                identity_row(&id_a, "alice", alice),
                identity_row(&id_a, "bob", bob)
            ],
            alloc::vec![],
            EnterpriseIdentityIndexError::DuplicateIdentityId,
        ),
        (
            alloc::vec![identity_row(&id_a, "alice", alice)],
            alloc::vec![history(&id_b, bob)],
            EnterpriseIdentityIndexError::OrphanHistory,
        ),
        (
            alloc::vec![identity_row(&id_a, "alice", alice)],
            alloc::vec![history(&id_a, alice)],
            EnterpriseIdentityIndexError::DuplicateSubject,
        ),
    ];
    for (identities, history, expected) in cases {
        let rows = EnterpriseIdentityRows {
            identities,
            history,
        };
        let store = MemoryStore::holding(rows.clone());
        assert_eq!(length(&store, &keys), Err(expected));
        assert_eq!(store.rows(), rows);
    }
}

#[test]
fn a_full_index_refuses_inserts_but_still_deactivates() {
    let keys = set(1, &[]);
    let rows = EnterpriseIdentityRows {
        identities: (0..ENTERPRISE_IDENTITY_MAX_IDENTITIES)
            .map(|n| {
                let principal = alloc::format!("p{n}");
                let identity_id =
                    EnterpriseIdentityId::try_from(alloc::format!("{n:032x}")).test_unwrap();
                let subject = subject(&keys, &principal);
                identity_row(&identity_id, &principal, subject)
            })
            .collect(),
        history: alloc::vec![],
    };
    let store = MemoryStore::holding(rows);
    let crowded = with_enterprise_identity_index(&store, &keys, |index| {
        index.resolve_or_insert(&SequenceRng::new(), SCOPE, "newcomer")
    });
    assert_eq!(
        crowded,
        Err(EnterpriseIdentityIndexError::CapacityExhausted)
    );
    assert_eq!(store.commits.get(), 0);

    let first = EnterpriseIdentityId::try_from(alloc::format!("{:032x}", 0)).test_unwrap();
    let in_force =
        with_enterprise_identity_index(&store, &keys, |index| index.deactivate(&first, u64::MAX));
    assert_eq!(in_force, Ok(u64::MAX));
    assert_eq!(store.commits.get(), 1);
}
