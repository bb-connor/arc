use std::collections::BTreeMap;
use std::fs;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_fiscal::{
    FiscalAuthorityState, FiscalBootstrapState, FiscalCharterBuilder, FiscalCharterRegistry,
    FiscalContinuityChange, FiscalContinuityCheckpointBuilder, FiscalDomain, FiscalDomainState,
    FiscalGenesisPolicy, FiscalRuntimeAdapter, FiscalRuntimeAdapterRegistry,
    FiscalRuntimeReadinessBuilder, VerifiedFiscalCharter, VerifiedFiscalContinuityAdvance,
    VerifiedFiscalContinuityCheckpoint, VerifiedFiscalRuntimeReadiness,
    FISCAL_RUNTIME_ADAPTER_COUNT,
};
use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn domains() -> Vec<FiscalDomainState> {
    [
        FiscalDomain::TierLimits,
        FiscalDomain::MarketplaceDiscountPerHundred,
        FiscalDomain::DecisionPremiumBasisPoints,
        FiscalDomain::InsurancePremiumSchedule,
        FiscalDomain::OpenMarketFeeAndBondSchedule,
    ]
    .into_iter()
    .map(FiscalDomainState::never_activated)
    .collect()
}

fn registry(version: &str) -> TestResult<FiscalRuntimeAdapterRegistry> {
    Ok(FiscalRuntimeAdapterRegistry::new(
        format!("build-{version}"),
        "chio.fiscal.runtime.v1".to_owned(),
        (0..FISCAL_RUNTIME_ADAPTER_COUNT)
            .map(|index| {
                FiscalRuntimeAdapter::new(format!("adapter-{index}"), format!("{version}.{index}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}

struct FiscalFixture {
    policy: FiscalGenesisPolicy,
    charter: VerifiedFiscalCharter,
    readiness: VerifiedFiscalRuntimeReadiness,
    genesis: VerifiedFiscalContinuityCheckpoint,
    authority: FiscalAuthorityState,
    next_readiness: VerifiedFiscalRuntimeReadiness,
    next_checkpoint: VerifiedFiscalContinuityCheckpoint,
    next_authority: FiscalAuthorityState,
    advance: VerifiedFiscalContinuityAdvance,
}

fn fiscal_fixture() -> TestResult<FiscalFixture> {
    let charter = VerifiedFiscalCharter::verify(
        FiscalCharterBuilder {
            governing_operator_id: "operator.example".to_owned(),
            governed_domains: vec![
                FiscalDomain::TierLimits,
                FiscalDomain::MarketplaceDiscountPerHundred,
                FiscalDomain::DecisionPremiumBasisPoints,
                FiscalDomain::InsurancePremiumSchedule,
                FiscalDomain::OpenMarketFeeAndBondSchedule,
            ],
            signer_keys: vec![key(1).public_key(), key(2).public_key()],
            approval_threshold: 2,
            timelock_seconds: 10,
            proposal_ttl_seconds: 100,
            approval_ttl_seconds: 50,
            issued_at: 10,
            expires_at: 1_000,
            issued_by: "operator.example".to_owned(),
            sequence: 1,
            predecessor_charter_digest: None,
        }
        .sign(&key(9))?,
    )?;
    let anchor_key = key(8);
    let mut bootstrap = BTreeMap::new();
    bootstrap.insert("USD".to_owned(), [100, 200, 300, 400]);
    let policy = FiscalGenesisPolicy::new(
        "operator.example".to_owned(),
        &charter,
        key(9).public_key(),
        "fiscal-anchor".to_owned(),
        "fiscal-main".to_owned(),
        1,
        anchor_key.public_key(),
        bootstrap,
    )?;
    let readiness_registry = registry("1")?;
    let readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 1,
            runtime_registry: readiness_registry.clone(),
            attested_at: 50,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        readiness_registry,
    )?;
    let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])?;
    let genesis = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 0,
            previous_checkpoint_digest: None,
            pinned_charter_id: charter.body().charter_id.clone(),
            pinned_charter_digest: charter.digest().to_owned(),
            pinned_charter_sequence: 1,
            runtime_readiness_digest: readiness.digest().to_owned(),
            domains: domains(),
            trusted_clock_high_water: 50,
            staged_transition: None,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        &charters,
    )?;
    let authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &genesis,
        FiscalBootstrapState::CharterPinned,
    )?;
    let next_registry = registry("2")?;
    let next_readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 2,
            runtime_registry: next_registry.clone(),
            attested_at: 60,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        next_registry,
    )?;
    let next_signed = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(genesis.digest().to_owned()),
        pinned_charter_id: charter.body().charter_id.clone(),
        pinned_charter_digest: charter.digest().to_owned(),
        pinned_charter_sequence: 1,
        runtime_readiness_digest: next_readiness.digest().to_owned(),
        domains: domains(),
        trusted_clock_high_water: 60,
        staged_transition: None,
    }
    .sign(&policy, &anchor_key)?;
    let change = FiscalContinuityChange::Readiness {
        current: Box::new(readiness.clone()),
        next: Box::new(next_readiness.clone()),
    };
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &genesis,
        next_signed,
        &policy,
        &charters,
        &change,
    )?;
    let next_checkpoint = advance.next().clone();
    let next_authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &next_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    Ok(FiscalFixture {
        policy,
        charter,
        readiness,
        genesis,
        authority,
        next_readiness,
        next_checkpoint,
        next_authority,
        advance,
    })
}

struct StoreFixture {
    _temp: TempDir,
    database: std::path::PathBuf,
    lock_root: std::path::PathBuf,
}

fn store_fixture() -> TestResult<StoreFixture> {
    let temp = tempfile::tempdir()?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    Ok(StoreFixture {
        _temp: temp,
        database,
        lock_root,
    })
}

#[test]
fn fiscal_schema_migrates_the_single_open_transition_guard() -> TestResult {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    initialize_fiscal_schema(&mut connection)?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 1 WHERE store_key = 'fiscal'",
        [],
    )?;
    connection.execute("DROP INDEX fiscal_one_open_transition", [])?;

    initialize_fiscal_schema(&mut connection)?;

    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'fiscal'",
        [],
        |row| row.get(0),
    )?;
    let index_present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = 'fiscal_one_open_transition')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, FISCAL_STORE_SUPPORTED_SCHEMA_VERSION);
    assert!(index_present);
    Ok(())
}

#[test]
fn fiscal_genesis_is_exact_idempotent_and_survives_restart() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    assert_eq!(store.load_authority_state()?, fixture.authority);
    drop(store);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    assert_eq!(
        reopened.fiscal_store().load_authority_state()?,
        fixture.authority
    );
    Ok(())
}

#[test]
fn staged_fiscal_advance_is_invisible_until_anchor_ack_and_finalize() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_runtime_readiness(&fixture.next_readiness, &fence)?;
    let staged = store.stage_advance(&fixture.advance, &fixture.next_authority, &fence)?;
    assert_eq!(staged.status, FiscalStageStatus::DbStaged);
    assert_eq!(store.load_authority_state()?, fixture.authority);
    assert_eq!(
        store
            .stage_advance(&fixture.advance, &fixture.next_authority, &fence)?
            .transition_id,
        staged.transition_id
    );
    drop(store);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let reopened_fence = reopened.mutation_fence();
    let store = reopened.fiscal_store();
    assert_eq!(
        store.load_transition(&staged.transition_id)?.status,
        FiscalStageStatus::DbStaged
    );
    let anchored = store.mark_anchor_advanced(
        &staged.transition_id,
        &fixture.next_checkpoint,
        &reopened_fence,
    )?;
    assert_eq!(anchored.status, FiscalStageStatus::FiscalAnchorAdvanced);
    assert_eq!(store.load_authority_state()?, fixture.authority);
    let finalized = store.finalize_advance(
        &staged.transition_id,
        &fixture.next_checkpoint,
        &fixture.next_authority,
        &reopened_fence,
    )?;
    assert_eq!(finalized.status, FiscalStageStatus::DbFinalized);
    assert_eq!(store.load_authority_state()?, fixture.next_authority);
    assert_eq!(
        fixture.next_checkpoint.body().runtime_readiness_digest,
        fixture.next_readiness.digest()
    );
    Ok(())
}

#[test]
fn unanchored_fiscal_stage_can_be_discarded_without_advancing_authority() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_runtime_readiness(&fixture.next_readiness, &fence)?;
    let staged = store.stage_advance(&fixture.advance, &fixture.next_authority, &fence)?;
    let discarded = store.discard_unanchored_stage(&staged.transition_id, &fence)?;
    assert_eq!(discarded.status, FiscalStageStatus::Discarded);
    assert_eq!(store.load_authority_state()?, fixture.authority);
    assert_eq!(sha256_hex(&discarded.proof_json), staged.transition_id);
    Ok(())
}
