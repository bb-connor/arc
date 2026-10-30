//! Concurrent first sight of one bearer token, and root tags under the
//! shared tenant index key set. Every refusal is pinned to its exact error.

#[path = "root_exchange_support/mod.rs"]
mod support;

use std::sync::Barrier;

use chio_core::root_authority::Sha256Digest;
use chio_core::tenant_index::{IndexDomain, TenantIndexKey, TenantIndexKeySet};
use chio_store_sqlite::root_exchange_store::{
    MintOutcome, RootExchangeStoreError as E, RootTagInputs, RootTags, RootTenantIndex,
};
use support::{Admit, Case, Env, RevokedTenant, TestResult, NOW};

const FIRST_SIGHTS: u8 = 8;

fn raw_count(env: &Env, table: &str) -> TestResult<i64> {
    Ok(env
        .fixture
        .raw()?
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?)
}

/// `FIRST_SIGHTS` bearer intakes of one token race; `same_replay` selects
/// whether they share one replay key or each straddle a clock second.
fn race_first_sights(same_replay: bool) -> TestResult {
    let env = Env::new()?;
    let cases = (0..FIRST_SIGHTS)
        .map(|index| {
            let mut case = Case::static_bearer(&format!("cap-{index}"))?;
            if !same_replay {
                case.replay = 0x60 + index;
            }
            Ok(case)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let barrier = Barrier::new(cases.len());
    let outcomes = std::thread::scope(|scope| {
        let workers: Vec<_> = cases
            .iter()
            .map(|case| {
                let env = &env;
                let barrier = &barrier;
                scope.spawn(move || -> Result<MintOutcome, String> {
                    let built = case.build().map_err(|error| error.to_string())?;
                    barrier.wait();
                    env.store
                        .mint_anchored_root(
                            &built.request(case),
                            &Admit,
                            &env.fence,
                            support::ms(NOW),
                        )
                        .map_err(|error| error.to_string())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| "first sight worker panicked".to_string())?
            })
            .collect::<Result<Vec<_>, String>>()
    })?;
    let mut minted = Vec::new();
    let mut recovered = Vec::new();
    for outcome in outcomes {
        match outcome {
            MintOutcome::Minted(root) => minted.push(root.capability.id),
            MintOutcome::Recovered(root) => recovered.push(root.capability.id),
        }
    }
    assert_eq!(minted.len(), 1, "{minted:?}");
    let winner = minted[0].clone();
    assert_eq!(
        recovered,
        vec![winner.clone(); usize::from(FIRST_SIGHTS) - 1]
    );
    assert_eq!(env.store.presentation(&winner)?.capability.id, winner);
    assert_eq!(raw_count(&env, "root_exchange_roots")?, 1);
    assert_eq!(raw_count(&env, "root_exchange_bearer_tokens")?, 1);
    assert_eq!(raw_count(&env, "root_exchange_replay")?, 1);
    Ok(())
}

#[test]
fn concurrent_first_sight_never_returns_an_uncovered_root() -> TestResult {
    race_first_sights(true)
}

#[test]
fn concurrent_first_sights_straddling_a_second_mint_one_root() -> TestResult {
    race_first_sights(false)
}

fn generation(byte: u8) -> TestResult<TenantIndexKey> {
    Ok(TenantIndexKey::from_set_key(&[byte; 32])?)
}

/// A key set whose active generation is `active` and whose retired
/// generations are `retired`.
fn key_set(active: u8, retired: &[u8]) -> TestResult<TenantIndexKeySet> {
    Ok(TenantIndexKeySet::new(
        generation(active)?,
        retired
            .iter()
            .map(|byte| generation(*byte))
            .collect::<TestResult<Vec<_>>>()?,
    )?)
}

const INPUTS: RootTagInputs<'static> = RootTagInputs {
    issuer: "urn:chio:operator",
    principal: "dev:alice",
    tenant_value: "dev",
};

fn key_id(byte: u8) -> TestResult<Sha256Digest> {
    Ok(*key_set(byte, &[])?.active_key_id())
}

/// A static bearer root minted with tags derived under generation `active`.
fn minted_under(active: u8) -> TestResult<Env> {
    let env = Env::new()?;
    let keys = key_set(active, &[])?;
    let index = RootTenantIndex::open(&keys, &env.store)?;
    let mut case = Case::static_bearer("cap-1")?;
    case.tags = index.derive_tags(&INPUTS)?;
    case.candidates = index.candidate_tags(&INPUTS)?;
    env.minted(&case, &Admit, NOW)?;
    Ok(env)
}

#[test]
fn new_tags_use_the_active_generation() -> TestResult {
    let env = Env::new()?;
    let keys = key_set(1, &[2])?;
    let tags = RootTenantIndex::open(&keys, &env.store)?.derive_tags(&INPUTS)?;
    assert_eq!(tags.key_id(), key_id(1)?);
    assert_eq!(
        tags,
        RootTags {
            subject: keys.derive(IndexDomain::SubjectTag, b"urn:chio:operator\0dev:alice"),
            tenant: keys.derive(IndexDomain::TenantTag, b"urn:chio:operator\0dev"),
        }
    );
    Ok(())
}

#[test]
fn candidate_tags_cover_every_loaded_generation() -> TestResult {
    let env = Env::new()?;
    let before = RootTenantIndex::open(&key_set(1, &[])?, &env.store)?.derive_tags(&INPUTS)?;
    let rotated = key_set(2, &[1])?;
    let candidates = RootTenantIndex::open(&rotated, &env.store)?.candidate_tags(&INPUTS)?;
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].key_id(), key_id(2)?);
    assert_eq!(candidates[1], before);
    Ok(())
}

#[test]
fn startup_refuses_a_missing_referenced_generation() -> TestResult {
    let env = minted_under(1)?;
    assert_eq!(
        RootTenantIndex::open(&key_set(2, &[])?, &env.store).err(),
        Some(E::TagGenerationMissing { key_id: key_id(1)? })
    );
    assert_eq!(
        E::TagGenerationMissing { key_id: key_id(1)? }.to_string(),
        "tenant index key does not match the state directory"
    );
    RootTenantIndex::open(&key_set(2, &[1])?, &env.store)?;
    Ok(())
}

#[test]
fn revoke_under_n_then_mint_under_n_plus_1_refuses_with_real_tags() -> TestResult {
    let env = Env::new()?;
    let old = RootTenantIndex::open(&key_set(1, &[])?, &env.store)?.derive_tags(&INPUTS)?;
    let rotated = key_set(2, &[1])?;
    let index = RootTenantIndex::open(&rotated, &env.store)?;
    let mut case = Case::static_bearer("cap-1")?;
    case.tags = index.derive_tags(&INPUTS)?;
    case.candidates = index.candidate_tags(&INPUTS)?;
    assert_eq!(
        env.refused(&case, &RevokedTenant(old), NOW)?,
        E::Revoked {
            entry_id: "rev-tenant-1".into()
        }
    );
    Ok(())
}

#[test]
fn tag_under_unknown_key_id_refuses() -> TestResult {
    let env = Env::new()?;
    let presented = RootTenantIndex::open(&key_set(3, &[])?, &env.store)?.derive_tags(&INPUTS)?;
    let keys = key_set(1, &[2])?;
    assert_eq!(
        RootTenantIndex::open(&keys, &env.store)?
            .verify_tags(&INPUTS, &presented)
            .err(),
        Some(E::TenantIndexKeyUnknown { key_id: key_id(3)? })
    );
    Ok(())
}

/// One plaintext for both the principal and the tenant value, so only the
/// purpose separates the two tags.
const SHARED: RootTagInputs<'static> = RootTagInputs {
    issuer: "urn:chio:operator",
    principal: "acme",
    tenant_value: "acme",
};

#[test]
fn tenant_tag_never_verifies_as_subject_tag() -> TestResult {
    let env = Env::new()?;
    let keys = key_set(1, &[])?;
    let index = RootTenantIndex::open(&keys, &env.store)?;
    let tags = index.derive_tags(&SHARED)?;
    assert_ne!(tags.subject, tags.tenant);
    index.verify_tags(&SHARED, &tags)?;
    let swapped = RootTags {
        subject: tags.tenant,
        tenant: tags.tenant,
    };
    assert_eq!(
        index.verify_tags(&SHARED, &swapped).err(),
        Some(E::TagMismatch)
    );
    Ok(())
}

#[test]
fn subject_tag_never_verifies_as_tenant_tag() -> TestResult {
    let env = Env::new()?;
    let keys = key_set(1, &[])?;
    let index = RootTenantIndex::open(&keys, &env.store)?;
    let tags = index.derive_tags(&SHARED)?;
    let swapped = RootTags {
        subject: tags.subject,
        tenant: tags.subject,
    };
    assert_eq!(
        index.verify_tags(&SHARED, &swapped).err(),
        Some(E::TagMismatch)
    );
    Ok(())
}

#[test]
fn tag_inputs_refuse_nul() -> TestResult {
    let env = Env::new()?;
    let keys = key_set(1, &[])?;
    let index = RootTenantIndex::open(&keys, &env.store)?;
    for (field, inputs) in [
        (
            "issuer",
            RootTagInputs {
                issuer: "urn:chio\0:operator",
                ..INPUTS
            },
        ),
        (
            "principal",
            RootTagInputs {
                principal: "dev\0alice",
                ..INPUTS
            },
        ),
        (
            "tenant_value",
            RootTagInputs {
                tenant_value: "de\0v",
                ..INPUTS
            },
        ),
    ] {
        assert_eq!(
            index.derive_tags(&inputs).err(),
            Some(E::TagInputContainsNul { field })
        );
        assert_eq!(
            index.candidate_tags(&inputs).err(),
            Some(E::TagInputContainsNul { field })
        );
    }
    Ok(())
}
