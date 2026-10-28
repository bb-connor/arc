//! Live replay bindings and bearer mappings removed through the owner's own
//! connection, which no data-version check sees: the next admission of the
//! same key refuses. Every refusal is pinned to its exact error.

#[path = "../../tests/root_exchange_support/mod.rs"]
mod support;

use super::RootExchangeStoreError as E;
use support::{digest, Admit, Case, Env, TestResult, NOW};

/// Delete rows through the serving owner's connection.
fn delete_through_owner(env: &Env, sql: &str) -> TestResult {
    let connection = env.store.connection.lock()?;
    connection.execute_batch(sql)?;
    Ok(())
}

#[test]
fn unexpired_client_assertion_deletion_refuses_the_next_bind() -> TestResult {
    let env = Env::new()?;
    env.store
        .bind_client_assertion(&digest(0x55), NOW + 60, &env.fence, env.at(NOW))?;
    delete_through_owner(&env, "DELETE FROM root_exchange_replay;")?;
    assert_eq!(
        env.store
            .bind_client_assertion(&digest(0x55), NOW + 120, &env.fence, env.at(NOW + 1))
            .err(),
        Some(E::ReplayBindingMissing {
            replay_key_digest: digest(0x55)
        })
    );
    Ok(())
}

#[test]
fn unexpired_mint_binding_deletion_refuses_the_next_mint() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::id_jag("cap-1")?, &Admit, NOW)?;
    delete_through_owner(&env, "DELETE FROM root_exchange_replay;")?;
    assert_eq!(
        env.refused(&Case::id_jag("cap-2")?, &Admit, NOW + 1)?,
        E::ReplayBindingMissing {
            replay_key_digest: digest(0x11)
        }
    );
    Ok(())
}

#[test]
fn unexpired_bearer_mapping_deletion_refuses_the_next_intake() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    delete_through_owner(&env, "DELETE FROM root_exchange_bearer_tokens;")?;
    let mut straddle = Case::static_bearer("cap-2")?;
    straddle.replay = 0x66;
    assert_eq!(
        env.refused(&straddle, &Admit, NOW + 1)?,
        E::BearerMappingMissing {
            token_digest: digest(0x44)
        }
    );
    Ok(())
}

#[test]
fn bearer_retry_still_recovers_and_explicit_repeat_still_refuses() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    assert_eq!(
        env.minted(&Case::static_bearer("cap-2")?, &Admit, NOW + 1)?,
        ("cap-1".to_string(), true)
    );
    let mut explicit = Case::id_jag("cap-3")?;
    explicit.replay = 0x21;
    env.minted(&explicit, &Admit, NOW + 2)?;
    let mut repeat = Case::id_jag("cap-4")?;
    repeat.replay = 0x21;
    assert_eq!(env.refused(&repeat, &Admit, NOW + 3)?, E::AssertionReplay);
    Ok(())
}
