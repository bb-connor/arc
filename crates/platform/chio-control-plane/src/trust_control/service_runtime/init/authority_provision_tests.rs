use super::*;
use chio_security_types::clock::{Clock, FixedClock};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixed(at: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(at))
}

fn config() -> TrustServiceConfig {
    TrustServiceConfig {
        transport: Default::default(),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        service_token: "token".to_string(),
        tenant_read_tokens: BTreeMap::new(),
        authority_workload_token: None,
        receipt_db_path: None,
        receipt_query_snapshot_quota_bytes: 2_147_483_648,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        authority_keyring_config_path: None,
        authority_keyring_receipt_anchor_root: None,
        budget_db_path: None,
        joint_authority_db_path: None,
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: None,
        verifier_challenge_db_path: None,
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: None,
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: Duration::from_millis(25),
        authority_replication_max_future_skew_seconds: 0,
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: None,
    }
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
