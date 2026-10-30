//! Outcome-unknown anchor syncs and crashes between a mint's commit, its
//! anchor sync and its response. Every refusal is pinned to its exact error.

use super::support;

use rusqlite::Transaction;

use super::{
    MintOutcome, MintRevocationCheck, MintRevocationRefusal, RevocationCandidate,
    RootExchangeStoreError as E,
};
use crate::serving_owner::SqliteServingOwner;
use crate::store_connection::test_support::panic_after_commit;
use support::{Admit, Case, Env, TestResult, NOW};

const POISONED: &str = "sqlite authority owner is poisoned after an outcome-unknown anchor sync";

/// Fails the anchor sync that follows this mint's commit: the check marks
/// the owner outcome-unknown inside the transaction, as a failed sync does,
/// and admits the root, so the commit lands and the sync after it refuses.
struct FailAnchorSync<'a>(&'a SqliteServingOwner);

impl MintRevocationCheck for FailAnchorSync<'_> {
    fn refuse_revoked_root(
        &self,
        _: &Transaction<'_>,
        _: &RevocationCandidate<'_>,
    ) -> Result<(), MintRevocationRefusal> {
        let _ = self.0.outcome_unknown("injected anchor sync failure");
        Ok(())
    }
}

fn root_rows(env: &Env) -> TestResult<i64> {
    Ok(env
        .fixture
        .raw()?
        .query_row("SELECT COUNT(*) FROM root_exchange_roots", [], |row| {
            row.get(0)
        })?)
}

/// Release the serving owner and open a fresh one over the same database.
fn reopen(env: Env) -> TestResult<Env> {
    let Env {
        fixture,
        owner,
        store,
        fence: _,
    } = env;
    drop(store);
    drop(owner);
    let owner = fixture.open()?;
    let store = owner.root_exchange_store();
    let fence = store.mutation_fence();
    Ok(Env {
        fixture,
        owner,
        store,
        fence,
    })
}

/// Mint `case` with its anchor sync failing, and check the outcome.
fn mint_with_failed_sync(case: &Case) -> TestResult<Env> {
    let env = Env::new()?;
    let built = case.build()?;
    let refused = env.store.mint_anchored_root(
        &built.request(case),
        &FailAnchorSync(&env.store.serving_owner),
        &env.fence,
        env.at(NOW),
    );
    assert_eq!(refused.err(), Some(E::OutcomeUnknown(POISONED.into())));
    assert_eq!(root_rows(&env)?, 1, "the root committed before the sync");
    Ok(env)
}

#[test]
fn anchor_sync_failure_reports_outcome_unknown() -> TestResult {
    let case = Case::static_bearer("cap-1")?;
    let env = mint_with_failed_sync(&case)?;
    let retry = Case::static_bearer("cap-2")?;
    assert_eq!(
        env.refused(&retry, &Admit, NOW + 1)?,
        E::OutcomeUnknown(POISONED.into())
    );
    assert_eq!(
        env.store.presentation("cap-1").err(),
        Some(E::OutcomeUnknown(POISONED.into()))
    );
    assert_eq!(root_rows(&env)?, 1);
    Ok(())
}

#[test]
fn retry_after_unknown_recovers_the_committed_root() -> TestResult {
    let env = reopen(mint_with_failed_sync(&Case::static_bearer("cap-1")?)?)?;
    assert_eq!(
        env.minted(&Case::static_bearer("cap-2")?, &Admit, NOW + 1)?,
        ("cap-1".to_string(), true)
    );
    assert_eq!(root_rows(&env)?, 1);
    Ok(())
}

#[test]
fn explicit_exchange_retry_after_unknown_refuses_replay() -> TestResult {
    let env = reopen(mint_with_failed_sync(&Case::id_jag("cap-1")?)?)?;
    assert_eq!(
        env.refused(&Case::id_jag("cap-2")?, &Admit, NOW + 1)?,
        E::AssertionReplay
    );
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");
    assert_eq!(root_rows(&env)?, 1);
    Ok(())
}

/// Stage `case`'s mint in a transaction that commits and then panics, after
/// the anchor sync when `sync_anchor` holds and before it otherwise.
fn crash_after_commit(env: &Env, case: &Case, sync_anchor: bool) -> TestResult {
    let built = case.build()?;
    let now = env.at(NOW);
    panic_after_commit(
        &env.store.connection,
        |tx| {
            let (outcome, changed) = env
                .store
                .stage_mint(tx, &built.request(case), &Admit, &env.fence, now)
                .unwrap_or_else(|error| panic!("stage the mint: {error}"));
            assert!(changed);
            assert!(matches!(outcome, MintOutcome::Minted(_)));
        },
        |connection| {
            if sync_anchor {
                env.store
                    .serving_owner
                    .sync_authority_anchor(connection)
                    .unwrap_or_else(|error| panic!("sync the anchor: {error}"));
            }
        },
    );
    Ok(())
}

#[test]
fn crash_after_commit_before_anchor_sync_recovers_after_reopen() -> TestResult {
    let env = Env::new()?;
    crash_after_commit(&env, &Case::static_bearer("cap-1")?, false)?;
    let read = env.store.presentation("cap-1");
    let fence = env
        .store
        .connection
        .fence()
        .map(ToString::to_string)
        .ok_or("the connection is not fenced")?;
    assert_eq!(read.err(), Some(E::Unavailable(fence)));
    assert_eq!(root_rows(&env)?, 1);

    let env = reopen(env)?;
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");
    assert_eq!(
        env.minted(&Case::static_bearer("cap-2")?, &Admit, NOW + 1)?,
        ("cap-1".to_string(), true)
    );
    Ok(())
}

#[test]
fn crash_after_anchor_sync_before_response_recovers_after_reopen() -> TestResult {
    let env = Env::new()?;
    crash_after_commit(&env, &Case::static_bearer("cap-1")?, true)?;
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");

    let env = reopen(env)?;
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");
    assert_eq!(
        env.minted(&Case::static_bearer("cap-2")?, &Admit, NOW + 1)?,
        ("cap-1".to_string(), true)
    );
    assert_eq!(root_rows(&env)?, 1);
    Ok(())
}
