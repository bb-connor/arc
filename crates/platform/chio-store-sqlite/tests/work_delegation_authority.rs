//! D1 allocation through the serving authority: every mutation is fenced,
//! command-bound and committed with the global authority chain.

use chio_core::crypto::{Keypair, PublicKey};
use chio_core::StoreMutationFence;
use chio_store_sqlite::delegation_store::{SqliteDelegationStore, SqliteDelegationStoreError};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteServingOwnerError};
use chio_workflow::delegation::*;
use serde_json::json;
use std::collections::BTreeSet;
use std::result::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Barrier;

#[path = "work_authority_support/serving.rs"]
mod serving;
use serving::{Fixture, TestResult};

const NOW_MS: u64 = 1_000_000;

fn key(n: u8) -> Keypair {
    Keypair::from_seed(&[n; 32])
}

fn cmd() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("command-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn contract(units: u64, depth: u16) -> WorkContract {
    WorkContract {
        effects: BTreeSet::from([Effect {
            server: "research".into(),
            tool: "analyze".into(),
        }]),
        readers: (1..=5).map(|n| key(n).public_key().to_hex()).collect(),
        max_units: units,
        currency: "USD".into(),
        expires_at: 2000,
        depth,
        acceptance: Acceptance {
            clauses: vec![Clause::IntegerRange {
                pointer: "/count".into(),
                min: 1,
                max: 10,
            }],
        },
    }
}

fn slot(id: &str, holder: u8, units: u64, depth: u16) -> WorkSlot {
    WorkSlot {
        id: id.into(),
        holder: key(holder).public_key(),
        contract: contract(units, depth),
    }
}

fn binding(id: &str, receiver: u8) -> DispatchBinding {
    DispatchBinding {
        slot_id: id.into(),
        receiver: key(receiver).public_key(),
        subject: key(2).public_key(),
        request_id: format!("request-{receiver}"),
        capability_hash: chio_core::crypto::sha256_hex(b"capability"),
        arguments_hash: chio_core::crypto::sha256_hex(b"arguments"),
        effect: Effect {
            server: "research".into(),
            tool: "analyze".into(),
        },
        max_units: 20,
        currency: "USD".into(),
    }
}

fn assert_open_invalid(fixture: &Fixture, message: &str) {
    let refusal = fixture
        .open()
        .err()
        .map(|error| error.downcast::<SqliteServingOwnerError>());
    assert!(
        matches!(
            &refusal,
            Some(Ok(error)) if matches!(**error, SqliteServingOwnerError::Invalid(ref m) if m == message)
        ),
        "{refusal:?}"
    );
}

struct Env {
    fixture: Fixture,
    owner: SqliteAuthorityStore,
    store: SqliteDelegationStore,
    fence: StoreMutationFence,
}

impl Env {
    fn new() -> TestResult<Self> {
        let fixture = Fixture::new(NOW_MS)?;
        let env = Self::open(fixture)?;
        env.store
            .create_root(&cmd(), slot("root", 1, 100, 3), &env.fence, NOW_MS)?;
        Ok(env)
    }

    fn open(fixture: Fixture) -> TestResult<Self> {
        let owner = fixture.open()?;
        let store = owner.delegation_store();
        let fence = store.mutation_fence();
        Ok(Self {
            fixture,
            owner,
            store,
            fence,
        })
    }

    fn reopen(self) -> TestResult<Self> {
        let Self {
            fixture,
            owner,
            store,
            ..
        } = self;
        drop(store);
        drop(owner);
        Self::open(fixture)
    }

    fn child(&self, id: &str, units: u64) -> Result<WorkSlot, SqliteDelegationStoreError> {
        let request = subdivision(&self.store, "root", 1, slot(id, 2, units, 2))?;
        self.store.subdivide(&cmd(), &request, &self.fence, NOW_MS)
    }

    fn child_of(
        &self,
        parent: &str,
        parent_holder: u8,
        id: &str,
        holder: u8,
        units: u64,
    ) -> Result<WorkSlot, SqliteDelegationStoreError> {
        let request = subdivision(
            &self.store,
            parent,
            parent_holder,
            slot(id, holder, units, 1),
        )?;
        self.store.subdivide(&cmd(), &request, &self.fence, NOW_MS)
    }

    fn select(
        &self,
        id: &str,
        receiver: u8,
        revision: u64,
        qualified: &[PublicKey],
    ) -> Result<(), SqliteDelegationStoreError> {
        let request = selection(&self.store, id, receiver, revision)?;
        self.store
            .select(&cmd(), &request, qualified, &self.fence, NOW_MS)
    }

    fn events(&self) -> TestResult<i64> {
        Ok(self.fixture.raw()?.query_row(
            "SELECT COUNT(*) FROM work_delegation_events",
            [],
            |row| row.get(0),
        )?)
    }
}

fn subdivision(
    store: &SqliteDelegationStore,
    parent: &str,
    parent_holder: u8,
    child: WorkSlot,
) -> Result<Signed<Subdivision>, SqliteDelegationStoreError> {
    Ok(Signed::sign(
        Subdivision {
            parent_id: parent.into(),
            parent_allocation_hash: store.allocation_digest(parent)?,
            child,
        },
        &key(parent_holder),
    )?)
}

fn selection(
    store: &SqliteDelegationStore,
    id: &str,
    receiver: u8,
    revision: u64,
) -> Result<Signed<Selection>, SqliteDelegationStoreError> {
    let offer = Signed::sign(
        WorkOffer {
            slot_id: id.into(),
            allocation_hash: store.allocation_digest(id)?,
            contract_hash: binding_digest(&store.slot(id)?)?,
            receiver: key(receiver).public_key(),
            effect: Effect {
                server: "research".into(),
                tool: "analyze".into(),
            },
            arguments_hash: chio_core::crypto::sha256_hex(b"arguments"),
            price_units: 20,
            expires_at: 1900,
        },
        &key(receiver),
    )?;
    Ok(Signed::sign(
        Selection {
            offer,
            request_id: format!("request-{receiver}"),
            capability_hash: chio_core::crypto::sha256_hex(b"capability"),
            expected_revision: revision,
        },
        &key(2),
    )?)
}

#[test]
fn nested_holders_allocate_without_copying_parent_capacity() -> TestResult {
    let env = Env::new()?;
    env.child("research", 60)?;
    env.child("independent", 40)?;
    let specialist = env.child_of("research", 2, "specialist", 3, 45)?;
    assert_eq!(specialist.holder, key(3).public_key());
    assert!(matches!(
        env.child("excess", 1),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Bounds))
    ));
    assert!(matches!(
        env.child_of("research", 2, "nested-excess", 3, 16),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Bounds))
    ));
    Ok(())
}

#[test]
fn rejected_permit_sealing_does_not_claim_the_allocation() -> TestResult {
    let env = Env::new()?;
    let mut large = slot("large", 2, 60, 2);
    large.contract.acceptance.clauses.push(Clause::Equals {
        pointer: "/large".into(),
        value: json!("x".repeat(63_650)),
    });
    let request = subdivision(&env.store, "root", 1, large)?;
    env.store.subdivide(&cmd(), &request, &env.fence, NOW_MS)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    env.select("large", 3, 0, &qualified)?;
    let events = env.events()?;
    let result = env
        .store
        .seal_dispatch(&cmd(), &binding("large", 3), &key(1), &env.fence, NOW_MS);
    assert!(
        matches!(
            &result,
            Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(reason)))
                if reason == "envelope byte limit"
        ),
        "{result:?}"
    );
    assert_eq!(env.events()?, events);
    env.select("large", 4, 1, &qualified)
        .map_err(|error| format!("provider replacement after refused sealing: {error}"))?;
    env.child("small", 40)?;
    env.select("small", 3, 0, &qualified)?;
    let permit =
        env.store
            .seal_dispatch(&cmd(), &binding("small", 3), &key(1), &env.fence, NOW_MS)?;
    assert_eq!(
        permit,
        env.store.seal_dispatch(
            &cmd(),
            &binding("small", 3),
            &key(1),
            &env.fence,
            NOW_MS + 1000,
        )?
    );
    Ok(())
}

#[test]
fn sibling_allocation_is_atomic_across_threads() -> TestResult {
    let env = Env::new()?;
    let barrier = Barrier::new(2);
    let successes = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|i| {
                let (env, barrier) = (&env, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    env.child(&format!("child-{i}"), 60).is_ok()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or(false))
            .filter(|granted| *granted)
            .count()
    });
    assert_eq!(successes, 1);
    Ok(())
}

#[test]
fn concurrent_over_allocation_grants_exactly_the_capacity() -> TestResult {
    let env = Env::new()?;
    let barrier = Barrier::new(8);
    let granted = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|i| {
                let (env, barrier) = (&env, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    env.child(&format!("share-{i}"), 20).is_ok()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or(false))
            .filter(|granted| *granted)
            .count()
    });
    assert_eq!(granted, 5);
    let held: u64 = (0..8)
        .filter_map(|i| env.store.slot(&format!("share-{i}")).ok())
        .map(|slot| slot.contract.max_units)
        .sum();
    assert_eq!(held, 100);
    assert!(matches!(
        env.child("one-more", 1),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Bounds))
    ));
    Ok(())
}

#[test]
fn mutation_requires_current_holder_and_untampered_signature() -> TestResult {
    let env = Env::new()?;
    let body = Subdivision {
        parent_id: "root".into(),
        parent_allocation_hash: env.store.allocation_digest("root")?,
        child: slot("child", 2, 30, 2),
    };
    let outsider = Signed::sign(body.clone(), &key(4))?;
    assert!(matches!(
        env.store.subdivide(&cmd(), &outsider, &env.fence, NOW_MS),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Authority))
    ));
    let mut signed = Signed::sign(body, &key(1))?;
    signed.body.child.contract.max_units = 31;
    assert!(matches!(
        env.store.subdivide(&cmd(), &signed, &env.fence, NOW_MS),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Signature))
    ));
    assert!(matches!(
        env.store.slot("child"),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(m))) if m == "unknown work slot"
    ));
    Ok(())
}

#[test]
fn subdivision_preserves_effect_readers_expiry_and_depth() -> TestResult {
    let env = Env::new()?;
    for mutation in 0..4 {
        let mut child = slot(&format!("bad-{mutation}"), 2, 30, 2);
        match mutation {
            0 => {
                child.contract.effects.insert(Effect {
                    server: "publish".into(),
                    tool: "send".into(),
                });
            }
            1 => {
                child.contract.readers.insert(key(9).public_key().to_hex());
            }
            2 => child.contract.expires_at = 2001,
            _ => child.contract.depth = 3,
        }
        let request = subdivision(&env.store, "root", 1, child)?;
        assert!(matches!(
            env.store.subdivide(&cmd(), &request, &env.fence, NOW_MS),
            Err(SqliteDelegationStoreError::Rule(DelegationError::Bounds))
        ));
    }
    Ok(())
}

#[test]
fn replay_cannot_change_a_child_or_move_it_to_another_parent() -> TestResult {
    let env = Env::new()?;
    env.child("child", 30)?;
    env.child("child", 30)?;
    assert!(matches!(
        env.child("child", 31),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    env.child("other", 70)?;
    assert!(matches!(
        env.child_of("other", 1, "child", 2, 30),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Authority))
    ));
    Ok(())
}

#[test]
fn provider_replacement_stops_at_dispatch_and_survives_reopen() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    env.select("leaf", 3, 0, &qualified)?;
    env.select("leaf", 4, 1, &qualified)?;
    assert!(matches!(
        env.select("leaf", 3, 0, &qualified),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    assert!(matches!(
        env.store
            .claim_dispatch(&cmd(), &binding("leaf", 3), &env.fence, NOW_MS),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Authority))
    ));
    let accepted = env
        .store
        .claim_dispatch(&cmd(), &binding("leaf", 4), &env.fence, NOW_MS)?;
    assert_eq!(accepted.slot.contract.max_units, 60);
    assert!(matches!(
        env.select("leaf", 3, 2, &qualified),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    let reopened = env.reopen()?;
    reopened.fixture.at(NOW_MS + 1000);
    reopened
        .store
        .claim_dispatch(&cmd(), &binding("leaf", 4), &reopened.fence, NOW_MS + 1000)?;
    let mut replaced = binding("leaf", 4);
    replaced.request_id = "fresh-retry".into();
    assert!(matches!(
        reopened
            .store
            .claim_dispatch(&cmd(), &replaced, &reopened.fence, NOW_MS + 1000),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    let request = subdivision(&reopened.store, "root", 1, slot("sibling", 2, 40, 1))?;
    reopened
        .store
        .subdivide(&cmd(), &request, &reopened.fence, NOW_MS + 1000)?;
    Ok(())
}

#[test]
fn selection_and_dispatch_cannot_race_into_different_providers() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    env.select("leaf", 3, 0, &qualified)?;
    let replacement = selection(&env.store, "leaf", 4, 1)?;
    let barrier = Barrier::new(2);
    let (dispatched, changed) = std::thread::scope(|scope| {
        let dispatch = scope.spawn(|| {
            barrier.wait();
            env.store
                .claim_dispatch(&cmd(), &binding("leaf", 3), &env.fence, NOW_MS)
                .is_ok()
        });
        barrier.wait();
        let changed = env
            .store
            .select(&cmd(), &replacement, &qualified, &env.fence, NOW_MS)
            .is_ok();
        (dispatch.join().unwrap_or(false), changed)
    });
    assert_ne!(changed, dispatched);
    Ok(())
}

#[test]
fn neither_containers_nor_unqualified_receivers_can_execute() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    assert!(matches!(
        env.select("leaf", 3, 0, &[]),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Authority))
    ));
    let mut s = selection(&env.store, "leaf", 3, 0)?.body;
    s.offer = Signed::sign(
        WorkOffer {
            slot_id: "root".into(),
            ..s.offer.body
        },
        &key(3),
    )?;
    assert!(matches!(
        env.store.select(
            &cmd(),
            &Signed::sign(s, &key(1))?,
            &[key(3).public_key()],
            &env.fence,
            NOW_MS
        ),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    assert!(matches!(
        env.child_of("leaf", 2, "late", 2, 1),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    Ok(())
}

#[test]
fn dispatch_checks_subject_currency_ceiling_capability_and_arguments() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    for mutation in 0..5 {
        let mut b = binding("leaf", 3);
        match mutation {
            0 => b.subject = key(5).public_key(),
            1 => b.currency = "EUR".into(),
            2 => b.max_units = 21,
            3 => b.capability_hash = chio_core::crypto::sha256_hex(b"new-capability"),
            _ => b.arguments_hash = chio_core::crypto::sha256_hex(b"other-input"),
        }
        let refusal = env
            .store
            .claim_dispatch(&cmd(), &b, &env.fence, NOW_MS)
            .err();
        assert!(
            matches!(
                (mutation, &refusal),
                (
                    0,
                    Some(SqliteDelegationStoreError::Rule(DelegationError::Authority))
                ) | (
                    1 | 2,
                    Some(SqliteDelegationStoreError::Rule(DelegationError::Bounds))
                ) | (
                    3 | 4,
                    Some(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
                )
            ),
            "mutation {mutation}: {refusal:?}"
        );
    }
    env.store
        .claim_dispatch(&cmd(), &binding("leaf", 3), &env.fence, NOW_MS)?;
    Ok(())
}

#[test]
fn expiry_and_noncanonical_numeric_envelopes_reject() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    let claim_at = env.fixture.at(1_900_000);
    assert!(matches!(
        env.store
            .claim_dispatch(&cmd(), &binding("leaf", 3), &env.fence, claim_at),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Expired))
    ));
    let request = subdivision(&env.store, "root", 1, slot("expired", 2, 1, 2))?;
    let expired_at = env.fixture.at(2_000_000);
    assert!(matches!(
        env.store
            .subdivide(&cmd(), &request, &env.fence, expired_at),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Expired))
    ));
    assert!(matches!(
        env.store.create_root(
            &cmd(),
            slot("overflow", 1, u64::MAX, 1),
            &env.fence,
            expired_at
        ),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(m))) if m == "envelope bounds"
    ));
    Ok(())
}

#[test]
fn predicates_validate_and_check_the_actual_json_result() -> TestResult {
    let mut a = contract(10, 1).acceptance;
    a.clauses.push(Clause::Equals {
        pointer: "/status".into(),
        value: json!("checked"),
    });
    a.validate()?;
    assert!(a.check(&json!({"count": 4, "status": "checked"})).is_ok());
    for v in [
        json!({"count": 11, "status":"checked"}),
        json!({"count": 2, "status":"bad"}),
        json!({"count": 2.0, "status":"checked"}),
        json!({"status":"checked"}),
    ] {
        assert!(matches!(a.check(&v), Err(DelegationError::Rejected)));
    }
    assert!(matches!(
        Acceptance { clauses: vec![] }.validate(),
        Err(DelegationError::Invalid(m)) if m == "acceptance clause count"
    ));
    assert!(matches!(
        Acceptance {
            clauses: vec![Clause::Equals {
                pointer: "bad".into(),
                value: json!(true)
            }]
        }
        .validate(),
        Err(DelegationError::Invalid(m)) if m == "JSON pointer"
    ));
    assert!(matches!(
        Acceptance {
            clauses: vec![Clause::Equals {
                pointer: "/~2".into(),
                value: json!(true)
            }]
        }
        .validate(),
        Err(DelegationError::Invalid(m)) if m == "JSON pointer escape"
    ));
    Ok(())
}

#[test]
fn sealed_allocation_is_portable_and_cannot_be_reassigned() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    let b = binding("leaf", 3);
    let permit = env
        .store
        .seal_dispatch(&cmd(), &b, &key(1), &env.fence, NOW_MS)?;
    assert_eq!(
        permit,
        env.store
            .seal_dispatch(&cmd(), &b, &key(1), &env.fence, NOW_MS + 1000)?
    );
    env.fixture.at(NOW_MS + 1000);
    assert!(matches!(
        env.select("leaf", 4, 1, &[key(4).public_key()]),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    drop(env);
    verify_dispatch_permit(&permit, &b, 1002, &[key(1).public_key()])?;
    assert!(matches!(
        verify_dispatch_permit(&permit, &b, 1002, &[]),
        Err(DelegationError::Authority)
    ));
    let mut altered = permit.clone();
    altered.body.slot.contract.acceptance.clauses.clear();
    assert!(matches!(
        verify_dispatch_permit(&altered, &b, 1002, &[key(1).public_key()]),
        Err(DelegationError::Signature)
    ));
    let mut other = b.clone();
    other.receiver = key(4).public_key();
    assert!(matches!(
        verify_dispatch_permit(&permit, &other, 1002, &[key(1).public_key()]),
        Err(DelegationError::Authority)
    ));
    assert!(matches!(
        verify_dispatch_permit(&permit, &b, 1900, &[key(1).public_key()]),
        Err(DelegationError::Expired)
    ));
    Ok(())
}

#[test]
fn provider_offer_cannot_be_transplanted_to_different_terms_with_the_same_slot_id() -> TestResult {
    let original = Env::new()?;
    original
        .store
        .create_root(&cmd(), slot("leaf", 2, 60, 2), &original.fence, NOW_MS)?;
    let prior_terms = selection(&original.store, "leaf", 3, 0)?;
    let env = Env::new()?;
    let mut substituted = slot("leaf", 2, 60, 2);
    substituted.contract.acceptance = Acceptance {
        clauses: vec![Clause::Equals {
            pointer: "/status".into(),
            value: json!("different-terms"),
        }],
    };
    env.store
        .create_root(&cmd(), substituted, &env.fence, NOW_MS)?;
    let refused = env.store.select(
        &cmd(),
        &prior_terms,
        &[key(3).public_key()],
        &env.fence,
        NOW_MS,
    );
    assert!(matches!(
        refused,
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    Ok(())
}

#[test]
fn signed_subdivision_cannot_cross_allocator_or_root_namespaces() -> TestResult {
    for same_root_name in [false, true] {
        let a = Env::open(Fixture::new(NOW_MS)?)?;
        let b = Env::open(Fixture::new(NOW_MS)?)?;
        let second_root = if same_root_name { "root-a" } else { "root-b" };
        for (env, root) in [(&a, "root-a"), (&b, second_root)] {
            env.store
                .create_root(&cmd(), slot(root, 1, 100, 3), &env.fence, NOW_MS)?;
            let request = subdivision(&env.store, root, 1, slot("shared-parent", 2, 60, 2))?;
            env.store.subdivide(&cmd(), &request, &env.fence, NOW_MS)?;
        }
        let request = subdivision(&a.store, "shared-parent", 2, slot("worker", 3, 30, 1))?;
        a.store.subdivide(&cmd(), &request, &a.fence, NOW_MS)?;
        assert!(
            matches!(
                b.store.subdivide(&cmd(), &request, &b.fence, NOW_MS),
                Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
            ),
            "foreign signed mutation must reject"
        );
        assert!(matches!(
            b.store.slot("worker"),
            Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(m))) if m == "unknown work slot"
        ));
    }
    Ok(())
}

#[test]
fn signed_selection_cannot_cross_allocator_namespaces() -> TestResult {
    let a = Env::new()?;
    let b = Env::new()?;
    a.child("leaf", 60)?;
    b.child("leaf", 60)?;
    let request = selection(&a.store, "leaf", 3, 0)?;
    a.store
        .select(&cmd(), &request, &[key(3).public_key()], &a.fence, NOW_MS)?;
    assert!(matches!(
        b.store
            .select(&cmd(), &request, &[key(3).public_key()], &b.fence, NOW_MS),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    assert!(matches!(
        b.store
            .claim_dispatch(&cmd(), &binding("leaf", 3), &b.fence, NOW_MS),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    Ok(())
}

#[test]
fn allocator_namespace_survives_reopen_and_is_not_silently_recreated() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let digest = env.store.allocation_digest("leaf")?;
    let selected = selection(&env.store, "leaf", 3, 0)?;
    let env = env.reopen()?;
    assert_eq!(env.store.allocation_digest("leaf")?, digest);
    env.store.select(
        &cmd(),
        &selected,
        &[key(3).public_key()],
        &env.fence,
        NOW_MS,
    )?;
    let permit =
        env.store
            .seal_dispatch(&cmd(), &binding("leaf", 3), &key(1), &env.fence, NOW_MS)?;
    let mut transplanted = permit.body.clone();
    transplanted.allocation_hash = chio_core::crypto::sha256_hex(b"another-allocation");
    assert!(matches!(
        verify_dispatch_permit(
            &Signed::sign(transplanted, &key(1))?,
            &binding("leaf", 3),
            1001,
            &[key(1).public_key()],
        ),
        Err(DelegationError::Conflict)
    ));
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    let db = fixture.raw()?;
    db.execute_batch(
        "DROP TRIGGER work_delegation_namespace_no_delete;
         DELETE FROM work_delegation_namespace;",
    )?;
    assert_open_invalid(
        &fixture,
        "delegation schema differs from the canonical definition",
    );
    let count: i64 = db.query_row("SELECT count(*) FROM work_delegation_namespace", [], |r| {
        r.get(0)
    })?;
    assert_eq!(
        count, 0,
        "opening an issued store must not invent a replacement namespace"
    );
    Ok(())
}

#[test]
fn store_refuses_a_stale_schema_stamp() -> TestResult {
    let env = Env::new()?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    fixture.raw()?.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE chio_store_schema_versions SET version = 2 WHERE store_key = 'work_delegation';
         PRAGMA ignore_check_constraints = OFF;",
    )?;
    let error = fixture.open().err().ok_or("stale schema was admitted")?;
    assert!(matches!(
        error.downcast_ref::<SqliteServingOwnerError>(),
        Some(SqliteServingOwnerError::Schema(
            chio_store_sqlite::SchemaVersionError::StaleSchema {
                found: 2,
                current: 1
            }
        ))
    ));
    Ok(())
}

#[test]
fn store_refuses_populated_tables_without_a_schema_stamp() -> TestResult {
    let env = Env::new()?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    fixture.raw()?.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'work_delegation'",
        [],
    )?;
    let error = fixture
        .open()
        .err()
        .ok_or("missing namespace was admitted")?;
    assert!(matches!(error.downcast_ref::<SqliteServingOwnerError>(),
        Some(SqliteServingOwnerError::Schema(chio_store_sqlite::SchemaVersionError::MissingSchema { store_key })) if store_key == "work_delegation"));
    Ok(())
}

#[test]
fn store_refuses_a_missing_table() -> TestResult {
    let env = Env::new()?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    fixture
        .raw()?
        .execute_batch("DROP TABLE work_delegation_permits;")?;
    assert_open_invalid(
        &fixture,
        "delegation schema differs from the canonical definition",
    );
    Ok(())
}

#[test]
fn tampering_with_a_slot_row_fails_reopen() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    fixture.raw()?.execute(
        "UPDATE work_delegation_slots SET allocated = 0 WHERE slot_id = 'root'",
        [],
    )?;
    assert_open_invalid(
        &fixture,
        "delegation slot state differs from its committed event",
    );
    Ok(())
}

#[test]
fn stale_fence_is_rejected_without_state_change() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    env.select("leaf", 3, 0, &qualified)?;
    let stale = env.fence.clone();
    let env = env.reopen()?;
    assert!(env.fence.owner_epoch > stale.owner_epoch);

    let root_digest = env.store.allocation_digest("root")?;
    let leaf = env.store.slot("leaf")?;
    let events = env.events()?;

    let sibling = subdivision(&env.store, "root", 1, slot("sibling", 2, 40, 1))?;
    assert!(matches!(
        env.store.subdivide(&cmd(), &sibling, &stale, NOW_MS),
        Err(SqliteDelegationStoreError::Unavailable(m)) if m == "admission operation mutation was fenced"
    ));
    let replacement = selection(&env.store, "leaf", 4, 1)?;
    assert!(matches!(
        env.store
            .select(&cmd(), &replacement, &qualified, &stale, NOW_MS),
        Err(SqliteDelegationStoreError::Unavailable(m)) if m == "admission operation mutation was fenced"
    ));
    assert!(matches!(
        env.store
            .claim_dispatch(&cmd(), &binding("leaf", 3), &stale, NOW_MS),
        Err(SqliteDelegationStoreError::Unavailable(m)) if m == "admission operation mutation was fenced"
    ));
    assert!(matches!(
        env.store
            .seal_dispatch(&cmd(), &binding("leaf", 3), &key(1), &stale, NOW_MS),
        Err(SqliteDelegationStoreError::Unavailable(m)) if m == "admission operation mutation was fenced"
    ));
    assert!(matches!(
        env.store
            .create_root(&cmd(), slot("other-root", 1, 10, 1), &stale, NOW_MS),
        Err(SqliteDelegationStoreError::Unavailable(m)) if m == "admission operation mutation was fenced"
    ));

    assert!(matches!(
        env.store.slot("sibling"),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(m))) if m == "unknown work slot"
    ));
    assert!(matches!(
        env.store.slot("other-root"),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(m))) if m == "unknown work slot"
    ));
    assert_eq!(env.store.allocation_digest("root")?, root_digest);
    assert_eq!(env.store.slot("leaf")?, leaf);
    assert_eq!(env.events()?, events);
    assert!(env
        .store
        .historical_dispatch(&binding("leaf", 3), &key(1).public_key())?
        .is_none());

    env.store
        .subdivide(&cmd(), &sibling, &env.fence, NOW_MS)
        .map_err(|error| format!("current fence must still mutate: {error}"))?;
    Ok(())
}

#[test]
fn changed_command_body_conflicts_while_exact_replay_changes_nothing() -> TestResult {
    let env = Env::new()?;
    let command = cmd();
    let first = subdivision(&env.store, "root", 1, slot("a", 2, 30, 1))?;
    env.store.subdivide(&command, &first, &env.fence, NOW_MS)?;
    let events = env.events()?;
    let digest = env.store.allocation_digest("a")?;

    let replayed = env.store.subdivide(&command, &first, &env.fence, NOW_MS)?;
    assert_eq!(replayed, slot("a", 2, 30, 1));
    assert_eq!(env.events()?, events);

    let changed = subdivision(&env.store, "root", 1, slot("b", 2, 30, 1))?;
    assert!(matches!(
        env.store.subdivide(&command, &changed, &env.fence, NOW_MS),
        Err(SqliteDelegationStoreError::CommandConflict)
    ));
    assert!(matches!(
        env.store.slot("b"),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Invalid(m))) if m == "unknown work slot"
    ));
    assert_eq!(env.events()?, events);
    assert_eq!(env.store.allocation_digest("a")?, digest);

    env.select("a", 3, 0, &[key(3).public_key()])?;
    let selected = selection(&env.store, "a", 3, 0)?;
    let select_command = cmd();
    env.store.select(
        &select_command,
        &selected,
        &[key(3).public_key()],
        &env.fence,
        NOW_MS,
    )?;
    let after_select = env.events()?;
    env.store.select(
        &select_command,
        &selected,
        &[key(3).public_key()],
        &env.fence,
        NOW_MS,
    )?;
    assert_eq!(env.events()?, after_select);
    let other = selection(&env.store, "a", 4, 0)?;
    assert!(matches!(
        env.store.select(
            &select_command,
            &other,
            &[key(4).public_key()],
            &env.fence,
            NOW_MS
        ),
        Err(SqliteDelegationStoreError::CommandConflict)
    ));

    let claim_command = cmd();
    env.store
        .claim_dispatch(&claim_command, &binding("a", 3), &env.fence, NOW_MS)?;
    let after_claim = env.events()?;
    env.store
        .claim_dispatch(&claim_command, &binding("a", 3), &env.fence, NOW_MS)?;
    assert_eq!(env.events()?, after_claim);
    let mut changed_binding = binding("a", 3);
    changed_binding.max_units = 19;
    assert!(matches!(
        env.store
            .claim_dispatch(&claim_command, &changed_binding, &env.fence, NOW_MS),
        Err(SqliteDelegationStoreError::CommandConflict)
    ));
    assert_eq!(env.events()?, after_claim);
    Ok(())
}

#[test]
fn selection_after_seal_is_refused_without_state_change() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    env.select("leaf", 3, 0, &qualified)?;
    let permit =
        env.store
            .seal_dispatch(&cmd(), &binding("leaf", 3), &key(1), &env.fence, NOW_MS)?;
    let events = env.events()?;
    let leaf = env.store.slot("leaf")?;
    for revision in [0, 1] {
        let refused = env.select("leaf", 4, revision, &qualified);
        assert!(
            matches!(refused, Err(SqliteDelegationStoreError::Rule(_))),
            "{refused:?}"
        );
    }
    assert_eq!(env.events()?, events);
    assert_eq!(env.store.slot("leaf")?, leaf);
    assert_eq!(
        env.store
            .historical_dispatch(&binding("leaf", 3), &key(1).public_key())?,
        Some(permit)
    );
    Ok(())
}

#[test]
fn live_seal_replay_returns_identical_bytes() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    let b = binding("leaf", 3);
    let command = cmd();
    let first = env
        .store
        .seal_dispatch(&command, &b, &key(1), &env.fence, NOW_MS)?;
    let events = env.events()?;
    env.fixture.at(NOW_MS + 5000);
    let same_command = env
        .store
        .seal_dispatch(&command, &b, &key(1), &env.fence, NOW_MS + 5000)?;
    let new_command = env
        .store
        .seal_dispatch(&cmd(), &b, &key(1), &env.fence, NOW_MS + 5000)?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&same_command)?,
        chio_core::canonical::canonical_json_bytes(&first)?
    );
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&new_command)?,
        chio_core::canonical::canonical_json_bytes(&first)?
    );
    assert_eq!(env.events()?, events);
    Ok(())
}

#[test]
fn historical_permit_outlives_expiry_while_fresh_dispatch_is_denied() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    let b = binding("leaf", 3);
    let permit = env
        .store
        .seal_dispatch(&cmd(), &b, &key(1), &env.fence, NOW_MS)?;
    let expired = env.fixture.at(2_000_000);
    let historical = env
        .store
        .historical_dispatch(&b, &key(1).public_key())?
        .ok_or("retained permit must stay readable")?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&historical)?,
        chio_core::canonical::canonical_json_bytes(&permit)?
    );
    assert!(matches!(
        env.store.claim_dispatch(&cmd(), &b, &env.fence, expired),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Expired))
    ));
    assert!(matches!(
        env.store
            .seal_dispatch(&cmd(), &b, &key(1), &env.fence, expired),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Expired))
    ));
    assert!(matches!(
        env.store.historical_dispatch(&b, &key(9).public_key()),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    Ok(())
}

#[test]
fn claim_without_seal_leaves_no_permit_and_keeps_capacity_consumed() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    env.select("leaf", 3, 0, &qualified)?;
    let b = binding("leaf", 3);
    env.store.claim_dispatch(&cmd(), &b, &env.fence, NOW_MS)?;
    assert!(env
        .store
        .historical_dispatch(&b, &key(1).public_key())?
        .is_none());
    let env = env.reopen()?;
    assert!(env
        .store
        .historical_dispatch(&b, &key(1).public_key())?
        .is_none());
    assert!(matches!(
        env.child("excess", 41),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Bounds))
    ));
    assert!(matches!(
        env.select("leaf", 4, 1, &qualified),
        Err(SqliteDelegationStoreError::Rule(DelegationError::Conflict))
    ));
    env.child("fits", 40)?;
    Ok(())
}

#[test]
fn reopen_preserves_namespace_allocation_digest_and_permit_bytes() -> TestResult {
    let env = Env::new()?;
    env.child("leaf", 60)?;
    env.select("leaf", 3, 0, &[key(3).public_key()])?;
    let b = binding("leaf", 3);
    let permit = env
        .store
        .seal_dispatch(&cmd(), &b, &key(1), &env.fence, NOW_MS)?;
    let digest = env.store.allocation_digest("leaf")?;
    let root_digest = env.store.allocation_digest("root")?;
    let leaf = env.store.slot("leaf")?;
    let namespace: String = env.fixture.raw()?.query_row(
        "SELECT namespace FROM work_delegation_namespace",
        [],
        |row| row.get(0),
    )?;
    let events = env.events()?;

    let env = env.reopen()?;
    let reopened_namespace: String = env.fixture.raw()?.query_row(
        "SELECT namespace FROM work_delegation_namespace",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(reopened_namespace, namespace);
    assert_eq!(env.store.allocation_digest("leaf")?, digest);
    assert_eq!(env.store.allocation_digest("root")?, root_digest);
    assert_eq!(env.store.slot("leaf")?, leaf);
    assert_eq!(env.events()?, events);
    let retained = env
        .store
        .historical_dispatch(&b, &key(1).public_key())?
        .ok_or("permit must survive reopen")?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&retained)?,
        chio_core::canonical::canonical_json_bytes(&permit)?
    );
    let replay = env
        .store
        .seal_dispatch(&cmd(), &b, &key(1), &env.fence, NOW_MS)?;
    assert_eq!(replay, permit);
    Ok(())
}
