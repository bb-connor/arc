#![cfg(test)]

use super::cluster_join_budget;
use super::{
    open_configured_joint_authority_store, validate_finding_purchase_runtime_dependencies,
    validate_injected_joint_authority_store, SqliteAuthorityStore, TrustServiceConfig,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[tokio::test]
async fn trust_transport_denies_public_plaintext_before_store_creation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let database = directory.path().join("must-not-exist.db");
    let mut config = test_config(database.clone());
    config.listen = "0.0.0.0:0".parse()?;
    let error = super::serve_async(config, None, None, None, None, None, None)
        .await
        .err()
        .ok_or("unsafe listener started")?;
    assert!(error.to_string().contains("non-loopback"));
    assert!(!database.exists());
    Ok(())
}

#[tokio::test]
async fn trust_transport_serves_authenticated_requests_over_tls(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&cert, identity.cert.pem())?;
    std::fs::write(&key, identity.key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let mut config = test_config(directory.path().join("unused.db"));
    config.joint_authority_db_path = None;
    config.revocation_db_path = Some(directory.path().join("revocations.db"));
    config.listen = address;
    config.transport = chio_http_serve::ServerTransportConfig {
        tls_cert: Some(cert),
        tls_key: Some(key),
        allow_plaintext: false,
    };
    let server = tokio::spawn(super::serve_async(
        config, None, None, None, None, None, None,
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(
            identity.cert.pem().as_bytes(),
        )?)
        .build()?;
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = client
                .get(format!(
                    "https://localhost:{}{}",
                    address.port(),
                    super::REVOCATIONS_PATH
                ))
                .bearer_auth("service-token")
                .send()
                .await
            {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.abort();
    let _ = server.await;
    Ok(())
}

fn test_config(joint_authority_db_path: PathBuf) -> TrustServiceConfig {
    TrustServiceConfig {
        transport: Default::default(),
        listen: "127.0.0.1:0"
            .parse()
            .unwrap_or_else(|error| panic!("fixed loopback address must parse: {error}")),
        service_token: "service-token".to_string(),
        tenant_read_tokens: BTreeMap::new(),
        authority_workload_token: None,
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        authority_keyring_config_path: None,
        authority_keyring_receipt_anchor_root: None,
        budget_db_path: None,
        joint_authority_db_path: Some(joint_authority_db_path),
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
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: None,
    }
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// The cluster-loop join must not add a second wait on top of the HTTP drain:
/// for every point at which the drain could return, the drain time already
/// spent plus the join budget it hands out stays within one drain window, so
/// the whole teardown fits the platform stop grace rather than overrunning it
/// and being escalated to a kill.
#[test]
fn cluster_join_never_extends_teardown_past_the_drain_window() {
    let drain = Duration::from_secs(25);
    // A drain that ran to its deadline leaves no budget at all.
    assert_eq!(cluster_join_budget(drain, drain), Duration::ZERO);
    for elapsed_ms in [0u64, 1_000, 12_500, 24_000, 25_000] {
        let elapsed = Duration::from_millis(elapsed_ms).min(drain);
        assert!(
            elapsed + cluster_join_budget(drain, elapsed) <= drain,
            "teardown at elapsed={elapsed:?} must stay within the drain window"
        );
    }
}

#[test]
fn purchase_runtime_requires_rail_and_authority_status_resolution() {
    assert!(validate_finding_purchase_runtime_dependencies(false, false, false).is_ok());
    assert!(validate_finding_purchase_runtime_dependencies(true, true, true).is_ok());

    let Err(missing_rail) = validate_finding_purchase_runtime_dependencies(true, false, true)
    else {
        panic!("purchase runtime without a rail must fail closed");
    };
    assert!(missing_rail.to_string().contains("settlement rail"));

    let Err(missing_status) = validate_finding_purchase_runtime_dependencies(true, true, false)
    else {
        panic!("purchase runtime without status resolution must fail closed");
    };
    assert!(missing_status
        .to_string()
        .contains("authority-status resolver"));
}

#[cfg(unix)]
#[test]
fn injected_challenge_authority_must_match_configured_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = chio_test_support::private_tempdir()?;
    secure_directory(temp.path())?;
    let configured_database = temp.path().join("configured.db");
    let configured_locks = temp.path().join("configured-locks");
    let injected_database = temp.path().join("injected.db");
    let injected_locks = temp.path().join("injected-locks");
    std::fs::create_dir(&configured_locks)?;
    secure_directory(&configured_locks)?;
    std::fs::create_dir(&injected_locks)?;
    secure_directory(&injected_locks)?;
    SqliteAuthorityStore::provision(&configured_database, &configured_locks)?;
    SqliteAuthorityStore::provision(&injected_database, &injected_locks)?;
    let injected = SqliteAuthorityStore::open_serving(&injected_database, &injected_locks)?;

    let matching = test_config(injected_database);
    validate_injected_joint_authority_store(&matching, &injected)?;

    let mismatched = test_config(configured_database);
    let error = match validate_injected_joint_authority_store(&mismatched, &injected) {
        Ok(()) => panic!("a different configured authority database must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("does not match"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configured_joint_authority_hardens_an_existing_lock_root(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temp = chio_test_support::private_tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("joint-authority.db");
    let lock_root = crate::durable_admission_lock_root(&database)?;
    std::fs::create_dir(&lock_root)?;
    std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o775))?;

    let store = open_configured_joint_authority_store(&test_config(database))?
        .ok_or("configured authority store was not opened")?;
    assert_eq!(
        std::fs::metadata(&lock_root)?.permissions().mode() & 0o077,
        0,
        "startup must remove group and other access before provisioning"
    );
    drop(store);
    Ok(())
}
