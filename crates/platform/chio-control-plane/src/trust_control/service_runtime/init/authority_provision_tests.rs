use super::*;
use chio_security_types::clock::{Clock, FixedClock};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixed(at: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(at))
}

fn config() -> TrustServiceConfig {
    TrustServiceConfig::for_tests()
}

#[test]
fn final_f11_startup_owner_uses_configured_clock_and_skew_without_future_floor_poisoning(
) -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let source_path = directory.path().join("source.sqlite3");
    let follower_path = directory.path().join("follower.sqlite3");
    let source = SqliteCapabilityAuthority::open_with_clock(&source_path, fixed(100))?;
    let anchor = source.initialize_replication("startup-owner-clock")?;
    let follower = SqliteCapabilityAuthority::open_with_clock(&follower_path, fixed(100))?;
    follower.pin_replication_anchor(&anchor)?;
    follower.apply_signed_snapshot(&source.signed_snapshot()?)?;
    let source = SqliteCapabilityAuthority::open_with_clock(&source_path, fixed(160))?;
    source.rotate()?;
    let envelope = source.signed_snapshot()?;
    let policy = chio_kernel::authority::replication::AuthorityEnvelopeClockPolicy::new(60)?;
    let follower = SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
        &follower_path,
        fixed(101),
        policy,
    )?;
    follower.apply_signed_snapshot(&envelope)?;
    let mut config = config();
    config.authority_db_path = Some(follower_path.clone());
    config.authority_replication_max_future_skew_seconds = 60;
    provision_service_authority(&config, fixed(101))?;
    let reopened = chio_store_sqlite::authority::SqliteAuthorityInspection::open_existing_with_clock_and_replication_policy(
        &follower_path, fixed(101), policy,
    )?;
    let status = reopened.verification_status()?.status;
    assert_eq!(status.generation, 2);
    assert!(
        !status
            .trusted_public_keys
            .contains(&source.status()?.public_key),
        "startup activated a future issuer"
    );
    assert!(matches!(
        provision_service_authority(&config, fixed(100)),
        Err(CliError::AuthorityStore(
            chio_kernel::AuthorityStoreError::Clock(
                chio_security_types::clock::ClockError::WallClockRegression
            )
        ))
    ));
    Ok(())
}

#[test]
fn final_f11_startup_owner_keeps_zero_skew_refusal_explicit() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("source.sqlite3");
    let source = SqliteCapabilityAuthority::open_with_clock(&path, fixed(100))?;
    source.initialize_replication("startup-zero-skew")?;
    let mut config = config();
    config.authority_db_path = Some(path);
    assert!(matches!(
        provision_service_authority(&config, fixed(99)),
        Err(CliError::AuthorityStore(
            chio_kernel::AuthorityStoreError::Clock(
                chio_security_types::clock::ClockError::WallClockRegression
            )
        ))
    ));
    Ok(())
}

#[test]
fn final_f11_startup_owner_never_recreates_keyring_owned_plain_seed() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let seed = directory.path().join("keyring-owned.seed");
    let mut config = config();
    config.authority_seed_path = Some(seed.clone());
    config.authority_keyring_config_path = Some(directory.path().join("keyring.json"));
    provision_service_authority(&config, fixed(100))?;
    assert!(
        !seed.exists(),
        "plain owner provisioning recreated keyring custody"
    );
    Ok(())
}
