//! Observable delegation boundaries, including independent SQLite connections.
use chio_core::crypto::Keypair;
use chio_workflow::delegation::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn key(n: u8) -> Keypair {
    Keypair::from_seed(&[n; 32])
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
fn setup() -> Result<(tempfile::TempDir, Arc<DelegationStore>)> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(DelegationStore::open(dir.path().join("allocation.db"))?);
    store.create_root(slot("root", 1, 100, 3))?;
    Ok((dir, store))
}
fn child(store: &DelegationStore, id: &str, units: u64) -> Result {
    store.subdivide(
        &Signed::sign(
            Subdivision {
                parent_id: "root".into(),
                child: slot(id, 2, units, 2),
            },
            &key(1),
        )?,
        1000,
    )?;
    Ok(())
}
fn selection(id: &str, receiver: u8, revision: u64) -> Result<Signed<Selection>> {
    Ok(Signed::sign(
        Selection {
            offer: Signed::sign(
                WorkOffer {
                    slot_id: id.into(),
                    contract_hash: binding_digest(&slot(id, 2, 60, 2))?,
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
            )?,
            request_id: format!("request-{receiver}"),
            capability_hash: chio_core::crypto::sha256_hex(b"capability"),
            expected_revision: revision,
        },
        &key(2),
    )?)
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

#[test]
fn nested_holders_allocate_without_copying_parent_capacity() -> Result {
    let (_dir, store) = setup()?;
    child(&store, "research", 60)?;
    child(&store, "independent", 40)?;
    store.subdivide(
        &Signed::sign(
            Subdivision {
                parent_id: "research".into(),
                child: slot("specialist", 3, 45, 1),
            },
            &key(2),
        )?,
        1000,
    )?;
    assert_eq!(store.slot("specialist")?.holder, key(3).public_key());
    assert!(child(&store, "excess", 1).is_err());
    assert!(store
        .subdivide(
            &Signed::sign(
                Subdivision {
                    parent_id: "research".into(),
                    child: slot("nested-excess", 3, 16, 1),
                },
                &key(2)
            )?,
            1000
        )
        .is_err());
    Ok(())
}

#[test]
fn sibling_allocation_is_atomic_across_connections() -> Result {
    let (dir, _store) = setup()?;
    let path = dir.path().join("allocation.db");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|i| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = DelegationStore::open(path);
                barrier.wait();
                store
                    .map(|s| child(&s, &format!("child-{i}"), 60).is_ok())
                    .map_err(|e| e.to_string())
            })
        })
        .collect();
    let mut successes = 0;
    for worker in workers {
        successes += usize::from(worker.join().map_err(|_| "allocation worker panicked")??);
    }
    assert_eq!(successes, 1);
    Ok(())
}

#[test]
fn mutation_requires_current_holder_and_untampered_signature() -> Result {
    let (_dir, store) = setup()?;
    let body = Subdivision {
        parent_id: "root".into(),
        child: slot("child", 2, 30, 2),
    };
    assert!(matches!(
        store.subdivide(&Signed::sign(body.clone(), &key(4))?, 1000),
        Err(DelegationError::Authority)
    ));
    let mut signed = Signed::sign(body, &key(1))?;
    signed.body.child.contract.max_units = 31;
    assert!(matches!(
        store.subdivide(&signed, 1000),
        Err(DelegationError::Signature)
    ));
    assert!(store.slot("child").is_err());
    Ok(())
}

#[test]
fn subdivision_preserves_effect_readers_expiry_and_depth() -> Result {
    let (_dir, store) = setup()?;
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
        assert!(matches!(
            store.subdivide(
                &Signed::sign(
                    Subdivision {
                        parent_id: "root".into(),
                        child
                    },
                    &key(1)
                )?,
                1000
            ),
            Err(DelegationError::Bounds)
        ));
    }
    Ok(())
}

#[test]
fn replay_cannot_change_a_child_or_move_it_to_another_parent() -> Result {
    let (_dir, store) = setup()?;
    child(&store, "child", 30)?;
    child(&store, "child", 30)?;
    assert!(child(&store, "child", 31).is_err());
    child(&store, "other", 70)?;
    assert!(store
        .subdivide(
            &Signed::sign(
                Subdivision {
                    parent_id: "other".into(),
                    child: slot("child", 2, 30, 1),
                },
                &key(2)
            )?,
            1000
        )
        .is_err());
    Ok(())
}

#[test]
fn provider_replacement_stops_at_dispatch_and_survives_reopen() -> Result {
    let (dir, store) = setup()?;
    child(&store, "leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    store.select(&selection("leaf", 3, 0)?, 1000, &qualified)?;
    store.select(&selection("leaf", 4, 1)?, 1000, &qualified)?;
    assert!(store
        .select(&selection("leaf", 3, 0)?, 1000, &qualified)
        .is_err());
    assert!(store.claim_dispatch(&binding("leaf", 3), 1000).is_err());
    let accepted = store.claim_dispatch(&binding("leaf", 4), 1000)?;
    assert_eq!(accepted.slot.contract.max_units, 60);
    assert!(store
        .select(&selection("leaf", 3, 2)?, 1000, &qualified)
        .is_err());
    let reopened = DelegationStore::open(dir.path().join("allocation.db"))?;
    reopened.claim_dispatch(&binding("leaf", 4), 1001)?;
    let mut replaced = binding("leaf", 4);
    replaced.request_id = "fresh-retry".into();
    assert!(reopened.claim_dispatch(&replaced, 1001).is_err());
    child(&reopened, "sibling", 40)?;
    Ok(())
}

#[test]
fn selection_and_dispatch_cannot_race_into_different_providers() -> Result {
    let (dir, store) = setup()?;
    child(&store, "leaf", 60)?;
    let qualified = [key(3).public_key(), key(4).public_key()];
    store.select(&selection("leaf", 3, 0)?, 1000, &qualified)?;
    let other = DelegationStore::open(dir.path().join("allocation.db"))?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b = barrier.clone();
    let s = store.clone();
    let dispatch = std::thread::spawn(move || {
        b.wait();
        s.claim_dispatch(&binding("leaf", 3), 1000).is_ok()
    });
    barrier.wait();
    let changed = other
        .select(&selection("leaf", 4, 1)?, 1000, &qualified)
        .is_ok();
    assert_ne!(
        changed,
        dispatch.join().map_err(|_| "dispatch worker panicked")?
    );
    Ok(())
}

#[test]
fn neither_containers_nor_unqualified_receivers_can_execute() -> Result {
    let (_dir, store) = setup()?;
    child(&store, "leaf", 60)?;
    assert!(store.select(&selection("leaf", 3, 0)?, 1000, &[]).is_err());
    let mut s = selection("leaf", 3, 0)?.body;
    s.offer = Signed::sign(
        WorkOffer {
            slot_id: "root".into(),
            ..s.offer.body
        },
        &key(3),
    )?;
    assert!(store
        .select(&Signed::sign(s, &key(1))?, 1000, &[key(3).public_key()])
        .is_err());
    store.select(&selection("leaf", 3, 0)?, 1000, &[key(3).public_key()])?;
    assert!(store
        .subdivide(
            &Signed::sign(
                Subdivision {
                    parent_id: "leaf".into(),
                    child: slot("late", 2, 1, 1),
                },
                &key(2)
            )?,
            1000
        )
        .is_err());
    Ok(())
}

#[test]
fn dispatch_checks_subject_currency_ceiling_capability_and_arguments() -> Result {
    let (_dir, store) = setup()?;
    child(&store, "leaf", 60)?;
    store.select(&selection("leaf", 3, 0)?, 1000, &[key(3).public_key()])?;
    for mutation in 0..5 {
        let mut b = binding("leaf", 3);
        match mutation {
            0 => b.subject = key(5).public_key(),
            1 => b.currency = "EUR".into(),
            2 => b.max_units = 21,
            3 => b.capability_hash = chio_core::crypto::sha256_hex(b"new-capability"),
            _ => b.arguments_hash = chio_core::crypto::sha256_hex(b"other-input"),
        }
        assert!(store.claim_dispatch(&b, 1000).is_err());
    }
    store.claim_dispatch(&binding("leaf", 3), 1000)?;
    Ok(())
}

#[test]
fn expiry_and_noncanonical_numeric_envelopes_reject() -> Result {
    let (_dir, store) = setup()?;
    let request = Signed::sign(
        Subdivision {
            parent_id: "root".into(),
            child: slot("expired", 2, 1, 2),
        },
        &key(1),
    )?;
    assert!(matches!(
        store.subdivide(&request, 2000),
        Err(DelegationError::Expired)
    ));
    assert!(store.create_root(slot("overflow", 1, u64::MAX, 1)).is_err());
    child(&store, "leaf", 60)?;
    store.select(&selection("leaf", 3, 0)?, 1000, &[key(3).public_key()])?;
    assert!(matches!(
        store.claim_dispatch(&binding("leaf", 3), 1900),
        Err(DelegationError::Expired)
    ));
    Ok(())
}

#[test]
fn predicates_validate_and_check_the_actual_json_result() -> Result {
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
        assert!(a.check(&v).is_err());
    }
    assert!(Acceptance { clauses: vec![] }.validate().is_err());
    assert!(Acceptance {
        clauses: vec![Clause::Equals {
            pointer: "bad".into(),
            value: json!(true)
        }]
    }
    .validate()
    .is_err());
    assert!(Acceptance {
        clauses: vec![Clause::Equals {
            pointer: "/~2".into(),
            value: json!(true)
        }]
    }
    .validate()
    .is_err());
    Ok(())
}

#[test]
fn sealed_allocation_is_portable_and_cannot_be_reassigned() -> Result {
    let (dir, store) = setup()?;
    child(&store, "leaf", 60)?;
    store.select(&selection("leaf", 3, 0)?, 1000, &[key(3).public_key()])?;
    let b = binding("leaf", 3);
    let permit = store.seal_dispatch(&b, 1000, &key(1))?;
    assert_eq!(permit, store.seal_dispatch(&b, 1001, &key(1))?);
    assert!(store
        .select(&selection("leaf", 4, 1)?, 1001, &[key(4).public_key()])
        .is_err());
    drop(store);
    drop(dir);
    // The issuing service and its database are gone; verification is local.
    verify_dispatch_permit(&permit, &b, 1002, &[key(1).public_key()])?;
    assert!(verify_dispatch_permit(&permit, &b, 1002, &[]).is_err());
    let mut altered = permit.clone();
    altered.body.slot.contract.acceptance.clauses.clear();
    assert!(verify_dispatch_permit(&altered, &b, 1002, &[key(1).public_key()]).is_err());
    let mut other = b.clone();
    other.receiver = key(4).public_key();
    assert!(verify_dispatch_permit(&permit, &other, 1002, &[key(1).public_key()]).is_err());
    assert!(verify_dispatch_permit(&permit, &b, 1900, &[key(1).public_key()]).is_err());
    Ok(())
}

#[test]
fn provider_offer_cannot_be_transplanted_to_different_terms_with_the_same_slot_id() -> Result {
    let dir = tempfile::tempdir()?;
    let store = DelegationStore::open(dir.path().join("other.db"))?;
    let mut substituted = slot("leaf", 2, 60, 2);
    substituted.contract.acceptance = Acceptance {
        clauses: vec![Clause::Equals {
            pointer: "/status".into(),
            value: json!("different-terms"),
        }],
    };
    store.create_root(substituted)?;
    assert!(store
        .select(&selection("leaf", 3, 0)?, 1000, &[key(3).public_key()])
        .is_err());
    Ok(())
}
